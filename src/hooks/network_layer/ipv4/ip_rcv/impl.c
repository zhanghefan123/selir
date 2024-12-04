#include "api/test.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "structure/path_validation_header.h"
#include <net/inet_ecn.h>

int self_defined_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev){
    return 0;
}


int path_validation_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev){
    // 1. 提取网络命名空间
    struct net* net = dev_net(dev);
    // 2. 拿到首部
    struct PathValidationHeader* pvh = pvh_hdr(skb);
    // 3. 进行消息的打印
    PRINT_PVH(pvh);
    // 4. 进行数据包的释放
    kfree_skb_reason(skb, SKB_DROP_REASON_IP_INHDR);
    return 0;
}


struct sk_buff* path_validation_rcv_core(struct sk_buff* skb, struct net* net){
    const struct PathValidationHeader *pvh;
    int drop_reason;
    u32 len;

    // 进行 pkt_type 的设置
    // - PACKET_HOST 代表目的地是本机
    // - PACKET_OTHERHOST 代表目的地是其他主机
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

    // 检查首部的长度
    // if (iph->ihl < 5 || iph->version != 4)
    //     goto inhdr_error;

    BUILD_BUG_ON(IPSTATS_MIB_ECT1PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_1);
    BUILD_BUG_ON(IPSTATS_MIB_ECT0PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_0);
    BUILD_BUG_ON(IPSTATS_MIB_CEPKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_CE);
    __IP_ADD_STATS(net,
                   IPSTATS_MIB_NOECTPKTS + (pvh->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, pvh->hdr_len))
        goto inhdr_error;

    pvh = pvh_hdr(skb);

    if (unlikely(ip_fast_csum((u8 *)pvh, pvh->hdr_len / 4)))
        goto csum_error;

    len = ntohs(pvh->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (pvh->hdr_len))
        goto inhdr_error;

    /* Our transport medium may have padded the buffer out. Now we know it
     * is IP we can trim to the true length of the frame.
     * Note this now means skb->len holds ntohs(iph->tot_len).
     */
    if (pskb_trim_rcsum(skb, len)) {
        __IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
        goto drop;
    }

    pvh = pvh_hdr(skb);
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