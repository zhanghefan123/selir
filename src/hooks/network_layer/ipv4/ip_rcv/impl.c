#include "api/test.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"
#include "structure/path_validation_header.h"
#include "structure/namespace/namespace.h"
#include "structure/crypto/bloom_filter.h"
#include <net/inet_ecn.h>

int self_defined_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev){
    return 0;
}

int pv_rcv_finish_core(struct net *net, struct sock *sk,
                       struct sk_buff *skb, struct net_device *dev,
                       const struct sk_buff *hint){
    // 1. path validation header 路径验证头部
    const struct PathValidationHeader *pvh = pvh_hdr(skb);
    // 2. 错误, 丢弃原因
    int err, drop_reason;
    drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;
    // 3. 路径验证数据结构
    struct PathValidationStructure* pvs = get_pvs_from_ns(net);
    // 4. 拿到接口表
    struct ArrayBasedInterfaceTable* abit = pvs->abit;
    int number_of_interfaces = abit->number_of_interfaces;
    int index;
    for(index = 0; index < number_of_interfaces; index++){
        if(dev->ifindex == abit->interfaces[index].index) {
            continue;
        } else {

        }
    }
    return NET_RX_SUCCESS;
}


int pv_rcv_finish(struct net*net, struct sock* sk, struct sk_buff* skb){
    struct net_device *dev = skb->dev;
    int ret;

    /* if ingress device is enslaved to an L3 master device pass the
     * skb to its handler for processing
     */
    //    skb = l3mdev_ip_rcv(skb);
    //    if (!skb)
    //        return NET_RX_SUCCESS;

    ret = pv_rcv_finish_core(net, sk, skb, dev, NULL);
    if (ret != NET_RX_DROP)
        ret = dst_input(skb);
    return ret;
}

int path_validation_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev){
    // 1. 提取网络命名空间
    struct net* net = dev_net(dev);
    // 2. 拿到首部
    struct PathValidationHeader* pvh = pvh_hdr(skb);
    struct PathValidationStructure* pvs = get_pvs_from_ns(net);
    // 3. 进行初级的校验
    skb = path_validation_rcv_validate(skb, net);
    // 4. 进行实际的转发
    path_validation_forward_packets(skb, pvs, net);
    // 5. 进行消息的打印
    PRINT_PVH(pvh);
    // 6. 进行数据包的释放
    kfree_skb_reason(skb, SKB_DROP_REASON_IP_INHDR);
    return 0;
}

/**
 * 进行实际的数据包的转发
 * @param skb
 * @param pvh
 */
void path_validation_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns){
    struct ArrayBasedInterfaceTable* abit = pvs->abit;
    int index;
    // 遍历所有的接口进行转发
    for(index = 0; index < abit->number_of_interfaces; index++){
        // 判断接口是否在




        pv_packet_forward(skb, abit->interfaces[index].interface, current_ns);
    }
}

struct sk_buff* path_validation_rcv_validate(struct sk_buff* skb, struct net* net){
    // 获取头部
    const struct PathValidationHeader *pvh;
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
    pvh = pvh_hdr(skb);

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
                   IPSTATS_MIB_NOECTPKTS + (pvh->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, pvh->hdr_len))
        goto inhdr_error;

    pvh = pvh_hdr(skb);

    // 如果校验和不正确的话, goto csum_error
    if (unlikely(ip_fast_csum((u8 *)pvh, pvh->hdr_len / 4)))
        goto csum_error;

    // 检查长度是否是合法的
    // --------------------------------------------------------
    // 获取 (网络层 + 传输层 + 应用层) 的总长度
    len = ntohs(pvh->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (pvh->hdr_len))
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

    pvh = pvh_hdr(skb);

    // 指向正确的传输层的头部
    skb->transport_header = skb->network_header + pvh->hdr_len;

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