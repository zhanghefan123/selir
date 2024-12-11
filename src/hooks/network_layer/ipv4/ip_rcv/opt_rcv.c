#include "api/test.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"
#include "structure/namespace/namespace.h"
#include "structure/session/session_table.h"
#include "hooks/network_layer/ipv4/ip_local_deliver/ip_local_deliver.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include <net/inet_ecn.h>
#include <linux/inetdevice.h>

int opt_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) {
    // 1. 初始化变量
    int process_result;
    struct net *current_ns = dev_net(dev);
    struct OptHeader *opt_header = opt_hdr(skb);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    // 2. 进行初级的校验
    skb = opt_rcv_validate(skb, current_ns);
    if (NULL == skb) {
        LOG_WITH_PREFIX("skb == NULL");
        return 0;
    }
    // 3. 进行数据包的打印
    PRINT_OPT_HEADER(opt_header);
    // 4. 进行不同的数据包的处理
    if (OPT_ESTABLISH_VERSION_NUMBER == opt_header->version) {
        process_result = opt_forward_session_establish_packets(skb, pvs, current_ns, orig_dev);
    } else if (OPT_DATA_VERSION_NUMBER == opt_header->version) {
        process_result = opt_forward_data_packets(skb, pvs, current_ns, orig_dev);
    } else {
        LOG_WITH_PREFIX("unsupported opt packet type");
        kfree_skb_reason(skb, SKB_DROP_REASON_IP_INHDR);
        return 0;
    }
    // 5. 进行数据包本地的处理
    if (NET_RX_SUCCESS == process_result) {
        LOG_WITH_PREFIX("local deliver");
        __be32 receive_interface_address = orig_dev->ip_ptr->ifa_list->ifa_address;
        pv_local_deliver(skb, opt_header->protocol, receive_interface_address);
        return 0;
    } else if (NET_RX_DROP == process_result) {
        LOG_WITH_PREFIX("packet drop");
        kfree_skb_reason(skb, SKB_DROP_REASON_IP_INHDR);
        return 0;
    } else {
        // do nothing
        return 0;
    }
}

int
opt_forward_session_establish_packets(struct sk_buff *skb, struct PathValidationStructure *pvs, struct net *current_ns,
                                      struct net_device *in_dev) {
    // 索引
    int index;
    // 拿到头部
    struct OptHeader *opt_header = opt_hdr(skb);
    // 拿到 path_length
    int path_length = *((__u16 *) get_first_opt_path_length_start_pointer(opt_header));
    // 进行路径的解析
    struct OptHop *path = (struct OptHop *) (get_first_opt_path_start_pointer(opt_header));
    // 拿到 session_id
    struct SessionID *session_id = (struct SessionID *) (get_first_opt_session_id_pointer(opt_header));
    // 拿到当前的索引
    int current_path_index = opt_header->current_path_index;
    // 拿到接口表
    struct ArrayBasedInterfaceTable *abit = pvs->abit;
    // 拿到会话表
    struct HashBasedSessionTable *hbst = pvs->hbst;
    // 当前节点id
    int current_node_id = pvs->node_id;
    // 源节点
    int source = opt_header->source;
    // 目的节点
    int destination = opt_header->dest;
    // 拿到当前的 link_identifier
    int current_link_identifier = path[current_path_index].link_id;
    // 如果当前节点 id == 目的节点
    if (current_node_id == destination) {
        // 路径长度
        int encrypt_count = path_length;
        // 需要进行前驱节点的记录
        int previous_node;
        if(0 == current_path_index){
            previous_node = source;
        } else {
            previous_node = path[current_path_index-1].node_id;
        }
        // 创建会话表项
        struct SessionTableEntry *ste = init_ste_in_dest(session_id, encrypt_count, previous_node);
        int count = 0;
        for (index = current_path_index; index >= 0; index--) { // 填充加密顺序
            ste->encrypt_order[count] = path[current_path_index].node_id;
            count += 1;
        }
        // 将路径添加到 hbst 之中
        add_entry_to_hbst(hbst, ste);
        // 不需要将这个包传输到上层了
        return NET_RX_DROP;
    } else {
        // 等待被填充的出接口
        struct net_device *output_interface = NULL;
        // 进行转发方向的决定
        for (index = 0; index < abit->number_of_interfaces; index++) {
            struct InterfaceTableEntry *ite = abit->interfaces[index];
            if (current_link_identifier == ite->link_identifier) {
                output_interface = ite->interface;
                break;
            }
        }
        // 需要进行前驱节点的记录
        int previous_node;
        if (0 == current_path_index) {
            previous_node = source;
        } else {
            previous_node = path[current_path_index-1].node_id;
        }
        // 创建会话表项目
        struct SessionTableEntry *ste = init_ste_in_intermediate(session_id, output_interface, previous_node);
        // 将会话表项添加到 hbst 之中
        add_entry_to_hbst(hbst, ste);
        // 进行 current_path_index 的更新
        opt_header->current_path_index += 1;
        // 在更新完了 current_path_index 之后一定需要进行 check 的更新
        opt_send_check(opt_header);
        // 进行数据包的转发
        if (NULL != output_interface) {
            pv_packet_forward(skb, output_interface, current_ns);
        }
        return NET_RX_NOTHING;
    }
}

static unsigned char *calculate_session_key(int current_node_id, struct shash_desc *hmac_api, struct OptHeader *opt_header) {
    unsigned char *session_id_pointer = get_other_opt_session_id_start_pointer(opt_header);
    char secret_value[20];
    snprintf(secret_value, sizeof(secret_value), "key-%d", current_node_id);
    unsigned char *session_key = calculate_hmac(hmac_api,
                                                session_id_pointer,
                                                sizeof(struct SessionID),
                                                (unsigned char *) (secret_value),
                                                (int) (strlen(secret_value)));
    return session_key;
}

/**
 * 进行上游节点是否正确转发的校验
 * @param opt_header 同步
 * @param pvs 路径验证结构体
 * @param ste 会话表项
 * @param session_key 会话密钥
 * @return 返回是否验证成功
 */
static bool proof_verification(struct OptHeader *opt_header,
                               struct PathValidationStructure *pvs,
                               struct SessionTableEntry *ste,
                               unsigned char* session_key) {
    // 1. 获取包内指针
    unsigned char *pvf_start_pointer = get_other_opt_pvf_start_pointer(opt_header);
    unsigned char *hash_start_pointer = get_other_opt_hash_start_pointer(opt_header);
    time64_t * time_stamp_pointer = (time64_t *) get_other_opt_timestamp_start_pointer(opt_header);
    struct OptOpv *opvs = (struct OptOpv *) (get_other_opt_opv_start_pointer(opt_header));
    int current_path_index = opt_header->current_path_index;
    // 2. 计算 combination
    char combination[100];
    // 2.1 拼接前一个 pvf
    memcpy(combination, pvf_start_pointer, PVF_LENGTH);
    // 2.2 拼接 data hash
    memcpy(combination + PVF_LENGTH, hash_start_pointer, HASH_LENGTH);
    // 2.2 拼接前驱节点
    *((int *) (combination + PVF_LENGTH + HASH_LENGTH)) = ste->previous_node;
    // 2.4 拼接 timestamp
    *((time64_t *) (combination + PVF_LENGTH + HASH_LENGTH + sizeof(int))) = (*time_stamp_pointer);
    // 2.5 进行 combination 的打印
    printk(KERN_EMERG "previous node %d\n", ste->previous_node);
    print_memory_in_hex(session_key, HMAC_OUTPUT_LENGTH);
    print_memory_in_hex(pvf_start_pointer, PVF_LENGTH);
    // 3. 利用 session_key 计算 opv
    unsigned char *hmac_result = calculate_hmac(pvs->hmac_api,
                                                (unsigned char *) combination,
                                                PVF_LENGTH + HASH_LENGTH + sizeof(int) + sizeof(time64_t),
                                                session_key,
                                                HMAC_OUTPUT_LENGTH);

    // 4. 进行比较, 判断是否验证成功
    bool result = memory_compare((unsigned char *) (&(opvs[current_path_index])), hmac_result, OPV_LENGTH);

    // 5. 进行 hmac_result 的释放 / session_key 先不进行释放, 一会儿还要用来进行 pvf 的更新。
    kfree(hmac_result);

    // 6. 进行结果的返回
    return result;
}

/**
 * 进行 proof 的更新
 * @param opt_header opt 头部
 * @param hmac_api hmac api
 * @param session_key 会话的密钥
 */
static void proof_update(struct OptHeader *opt_header, struct shash_desc* hmac_api, unsigned char* session_key) {
    // 1. 获取包内指针
    unsigned char *pvf_start_pointer = get_other_opt_pvf_start_pointer(opt_header);
    // 2. 利用 session_key 来计算 mac
    unsigned char* hmac_result = calculate_hmac(hmac_api,
                                                pvf_start_pointer,
                                                PVF_LENGTH,
                                                session_key,
                                                HMAC_OUTPUT_LENGTH);
    // 3. 更新到 pvf 之中
    memcpy(pvf_start_pointer, hmac_result, PVF_LENGTH);

    // 4. 进行 hmac_result 的 free
    kfree(hmac_result);
}


/**
 * 进行 opt 数据包的转发
 * @param skb 数据包
 * @param pvs 路径验证数据结构
 * @param current_ns 当前的网络命名空间
 * @param in_dev 入接口
 * @return
 */
int opt_forward_data_packets(struct sk_buff *skb, struct PathValidationStructure *pvs, struct net *current_ns,
                             struct net_device *in_dev) {
    // 1.是否本地提交
    bool local_deliver;
    // 2.找到 opt_header
    struct OptHeader *opt_header = opt_hdr(skb);
    // 3.找到 session_id
    struct SessionID *session_id = (struct SessionID *) get_other_opt_session_id_start_pointer(opt_header);
    // 4.进行相应的表项的查找
    struct SessionTableEntry *ste = find_ste_in_hbst(pvs->hbst, session_id);
    // 6.进行 session_key 的计算
    unsigned char* session_key = calculate_session_key(pvs->node_id, pvs->hmac_api, opt_header);
    // 7.进行结果的验证
    bool result = proof_verification(opt_header, pvs, ste, session_key);
    // 8.进行字段的更新
    if (result){ // 如果验证是成功的, 则进行字段的更新
        LOG_WITH_PREFIX("verification succeed");
        proof_update(opt_header, pvs->hmac_api, session_key);
    } else { // 如果验证是失败的, 则直接进行包的丢弃
        LOG_WITH_PREFIX("verification failed");
        return NET_RX_DROP;
    }
    // 9.验证和更新完成之后, 就可以丢弃掉 session_key 了
    kfree(session_key);
    // 10. 还需要进行 current_path_index 的更新
    opt_header->current_path_index += 1;
    // 10. 进行校验和的更新
    opt_send_check(opt_header);
    // 11. 进行相应的转发
    if (NULL != ste) {
        struct sk_buff *skb_copied = skb_copy(skb, GFP_KERNEL);
        pv_packet_forward(skb_copied, ste->output_interface, current_ns);
    } else {
        LOG_WITH_PREFIX("cannot find ste, not forward");
    }
    // 当前节点
    int current_node_id = pvs->node_id;
    // 判断是否到达了目的节点
    local_deliver = (current_node_id == opt_header->dest);
    if (local_deliver) {
        return NET_RX_SUCCESS;
    } else {
        return NET_RX_DROP;
    }
}

struct sk_buff *opt_rcv_validate(struct sk_buff *skb, struct net *net) {
    // 获取头部
    const struct OptHeader *opt_header;
    // 丢包的原因
    int drop_reason;
    // 总的长度
    u32 len;

    // 进行 pkt_type 的设置 (由于设置的是 BROADCAST_MAC 所以这里不行)
    // 1. PACKET_HOST 代表目的地是本机
    // 2. PACKET_OTHERHOST 代表目的地是其他主机
    skb->pkt_type = PACKET_HOST;

    /* When the interface is in promisc. mode, drop all the crap
     * that it receives, do not try to analyse it
     * 如果是其他主机，那么直接丢
     */
    if (skb->pkt_type == PACKET_OTHERHOST) {
        dev_core_stats_rx_otherhost_dropped_inc(skb->dev);
        drop_reason = SKB_DROP_REASON_OTHERHOST;
        goto drop;
    }

    __IP_UPD_PO_STATS(net, IPSTATS_MIB_IN, skb->len);

    skb = skb_share_check(skb, GFP_ATOMIC);
    if (!skb) {
        __IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
        goto out;
    }

    drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;

    // 确保存在足够的空间
    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        goto inhdr_error;

    // 解析网络层首部
    opt_header = opt_hdr(skb);

    /*
     *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
     *
     *	Is the datagram acceptable?
     *
     *	1.	Length at least the size of an ip header
     *	2.	Version of 4
     *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
     *	4.	Doesn't have a bogus length
     */

    BUILD_BUG_ON(IPSTATS_MIB_ECT1PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_1);
    BUILD_BUG_ON(IPSTATS_MIB_ECT0PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_0);
    BUILD_BUG_ON(IPSTATS_MIB_CEPKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_CE);
    __IP_ADD_STATS(net,
                   IPSTATS_MIB_NOECTPKTS + (opt_header->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, opt_header->hdr_len))
        goto inhdr_error;

    opt_header = opt_hdr(skb);

    // 如果校验和不正确的话, goto csum_error
    if (unlikely(ip_fast_csum((u8 *) opt_header, opt_header->hdr_len / 4))) {
        LOG_WITH_PREFIX("csum error");
        goto csum_error;
    }


    // 检查长度是否是合法的
    // --------------------------------------------------------
    // 获取 (网络层 + 传输层 + 应用层) 的总长度
    len = ntohs(opt_header->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (opt_header->hdr_len))
        goto inhdr_error;
    // --------------------------------------------------------

    /* Our transport medium may have padded the buffer out. Now we know it
     * is IP we can trim to the true length of the frame.
     * Note this now means skb->len holds ntohs(iph->tot_len).
     */
    if (pskb_trim_rcsum(skb, len)) {
        __IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
        goto drop;
    }

    opt_header = opt_hdr(skb);

    // 指向正确的传输层的头部
    skb->transport_header = skb->network_header + opt_header->hdr_len;

    /* Remove any debris in the socket control block */
    memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
    IPCB(skb)->iif = skb->skb_iif;

    /* Must drop socket now because of tproxy. */
    if (!skb_sk_is_prefetched(skb))
        skb_orphan(skb);

    return skb;

    csum_error:
    drop_reason = SKB_DROP_REASON_IP_CSUM;
    __IP_INC_STATS(net, IPSTATS_MIB_CSUMERRORS);
    inhdr_error:
    if (drop_reason == SKB_DROP_REASON_NOT_SPECIFIED)
        drop_reason = SKB_DROP_REASON_IP_INHDR;
    __IP_INC_STATS(net, IPSTATS_MIB_INHDRERRORS);
    drop:
    kfree_skb_reason(skb, drop_reason);
    out:
    return NULL;
}