#include "api/test.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "structure/namespace/namespace.h"
#include "structure/session/session_table.h"

int opt_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type *pt, struct net_device* orig_dev){
    // 1. 初始化变量
    struct net* current_ns = dev_net(dev);
    struct OptHeader* opt_header = opt_hdr(skb);
    struct PathValidationStructure* pvs = get_pvs_from_ns(current_ns);
    // 2. 进行初级的校验
    skb = opt_rcv_validate(skb, current_ns);
    // 3. 进行不同的数据包的处理
    if(OPT_ESTABLISH_VERSION_NUMBER == opt_header->version){
        opt_forward_establish_packets(skb, pvs, current_ns, orig_dev);
    } else if(OPT_DATA_VERSION_NUMBER == opt_header->version){
        opt_forward_data_packets(skb, pvs, current_ns, orig_dev);
    } else {
        LOG_WITH_PREFIX("unsupported opt packet type");
        kfree_skb_reason(skb, SKB_DROP_REASON_IP_INHDR);
        return 0;
    }
    // 3. 进行数据包的打印
    PRINT_OPT_HEADER(opt_header);
    // 进行数据包的释放
    kfree_skb_reason(skb, SKB_DROP_REASON_IP_INHDR);
    return 0;
}

int opt_forward_establish_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev){
    // 索引
    int index;
    // 拿到头部
    struct OptHeader* opt_header = opt_hdr(skb);
    // 拿到 path_length
    int path_length = *((__u16*)get_opt_path_length_start_pointer(opt_header));
    // 进行路径的解析
    struct OptHop* path = (struct OptHop*)(get_opt_path_start_pointer(opt_header));
    // 拿到 session_id
    struct SessionID* session_id = (struct SessionID*)(get_first_opt_session_id_pointer(opt_header));
    // 拿到当前的索引
    int current_path_index = opt_header->current_path_index;
    // 拿到接口表
    struct ArrayBasedInterfaceTable* abit = pvs->abit;
    // 拿到当前的 link_identifier
    int current_link_identifier = path[current_path_index].link_id;
    // output interface
    struct net_device* output_interface = NULL;
    // 进行转发方向的决定
    for(index = 0; index < abit->number_of_interfaces; index++){
        struct InterfaceTableEntry* ite = abit->interfaces[index];
        // 不能向入口回传
        if(in_dev->ifindex == ite->interface->ifindex){
            continue;
        } else {
            if(current_link_identifier == ite->link_identifier){
                output_interface = ite->interface;
                break;
            }
        }
    }
    // 构建上游节点
    int upstream_nodes_count = current_path_index + 1; // +1 means source
    for(index)


    // 将路径添加到 hbst 之中
    // --------------------------------------------------------------------------
    struct HashBasedSessionTable* hbst = pvs->hbst;
    struct SessionTableEntry* ste = init_ste_in_dest(session_id,)
    add_entry_to_hbst(hbst, ste);
    // --------------------------------------------------------------------------
}


int opt_forward_data_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev){

}

struct sk_buff* opt_rcv_validate(struct sk_buff* skb, struct net* net){
    // 获取头部
    const struct OptHeader* opt_header;
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
    if (unlikely(ip_fast_csum((u8 *)opt_header, opt_header->hdr_len / 4)))
    {
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