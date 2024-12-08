#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "structure/header/icing_header.h"
#include "structure/namespace/namespace.h"
#include "structure/crypto/crypto_structure.h"
#include <net/inet_ecn.h>

int icing_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev){
    // 1. 初始化变量
    struct net* net = dev_net(dev);
    struct ICINGHeader* icing_header = icing_hdr(skb);
    struct PathValidationStructure* pvs = get_pvs_from_ns(net);
    int process_result;
    // 2. 进行消息的打印
    PRINT_ICING_HEADER(icing_header);
    // 3. 进行初级的校验
    skb = icing_rcv_validate(skb, net);
    // 4. 进行实际的转发
    process_result = icing_forward_packets(skb, pvs, net, orig_dev);
    // 5. 在没能完整判断之前先进行数据包的释放
    kfree_skb_reason(skb, SKB_DROP_REASON_BPF_CGROUP_EGRESS);
    return 0;
}

struct sk_buff* icing_rcv_validate(struct sk_buff*skb, struct net* net){
    // 获取头部
    const struct ICINGHeader *icing_header;
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
    icing_header = icing_hdr(skb);

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
                   IPSTATS_MIB_NOECTPKTS + (icing_header->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, icing_header->hdr_len))
        goto inhdr_error;

    icing_header = icing_hdr(skb);

    // 如果校验和不正确的话, goto csum_error
    if (unlikely(ip_fast_csum((u8 *)icing_header, icing_header->hdr_len / 4)))
    {
        LOG_WITH_PREFIX("csum error");
        goto csum_error;
    }


    // 检查长度是否是合法的
    // --------------------------------------------------------
    // 获取 (网络层 + 传输层 + 应用层) 的总长度
    len = ntohs(icing_header->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (icing_header->hdr_len))
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

    icing_header = icing_hdr(skb);

    // 指向正确的传输层的头部
    skb->transport_header = skb->network_header + icing_header->hdr_len;

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

static bool proof_verification(struct ICINGHeader* icing_header, struct PathValidationStructure* pvs) {
    // 1. 变量定义
    bool result;
    int index;
    int current_node_id = pvs->node_id;
    int current_path_index = icing_header->current_path_index;
    int source = icing_header->source;

    struct shash_desc* hash_api = pvs->hash_api;
    struct shash_desc* hmac_api = pvs->hmac_api;
    struct NodeIdAndTag* path = (struct NodeIdAndTag*)(return_icing_path_start_pointer(icing_header));
    struct ProofAndHardner* proof_list = (struct ProofAndHardner*)(return_icing_proof_start_pointer(icing_header));
    // 2.计算哈希
    icing_header->check = 0; // 在计算哈希之前需要将校验和置为0
    unsigned char* static_fields_hash = calculate_hash(hash_api, (unsigned char*)(icing_header), sizeof(struct ICINGHeader));
    // 3.进行校验
    // 首先计算源和当前节点的 hmac
    char key_from_source_to_current[20];
    sprintf(key_from_source_to_current, "key-%d-%d", source, current_node_id);
    unsigned char *hmac_result_final = calculate_hmac(hmac_api,
                                                      static_fields_hash,
                                                      HASH_OUTPUT_LENGTH,
                                                      key_from_source_to_current);
    if(0 == current_path_index){
        result = memory_compare((unsigned char*)(&proof_list[current_path_index]),
                                hmac_result_final,
                                ICING_PROOF_LENGTH);
    } else {
        for(index = 0; index < current_path_index; index++){
            // 获取上游节点 id
            __u32 upstream_node = path[index].node_id;
            sprintf(key_from_source_to_current, "key-%d-%d", upstream_node, current_node_id);
            unsigned char *hmac_result_temp = calculate_hmac(hmac_api,
                                                        static_fields_hash,
                                                        HASH_OUTPUT_LENGTH,
                                                        key_from_source_to_current);
            memory_xor(hmac_result_final, hmac_result_temp, ICING_PROOF_LENGTH);
            kfree(hmac_result_temp);
        }
        result = memory_compare((unsigned char*)(&proof_list[current_path_index]),
                                hmac_result_final,
                                ICING_PROOF_LENGTH);
    }
    kfree(hmac_result_final);
    kfree(static_fields_hash);
    return result;
}

static void proof_update(void){

}

int icing_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev){
    bool result = proof_verification(icing_hdr(skb), pvs);
    if(result){
        LOG_WITH_PREFIX("verification succeed");
    } else {
        LOG_WITH_PREFIX("verification failed");
    }
    return 0;
}