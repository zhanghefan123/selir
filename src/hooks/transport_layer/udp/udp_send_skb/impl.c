#include <linux/udp.h>
#include "hooks/transport_layer/udp/udp_send_skb/udp_send_skb.h"
#include "hooks/network_layer/ipv4/ip_send_skb/ip_send_skb.h"

/**
 * 进行 udp 层的定义
 * @param skb 数据包
 * @param fl4 流信息
 * @param cork corking 状态
 * @return
 */
int self_defined_udp_send_skb(struct sk_buff *skb, struct flowi4 *fl4, struct inet_cork *cork, struct net_device* output_interface)
{
    struct sock *sk = skb->sk;
    struct inet_sock *inet = inet_sk(sk);
    struct udphdr *uh;
    int err;
    int is_udplite = IS_UDPLITE(sk);
    int offset = skb_transport_offset(skb);
    int len = skb->len - offset;
    int datalen = len - sizeof(*uh);
    __wsum csum = 0;

    /*
     * Create a UDP header
     */
    uh = udp_hdr(skb);
    uh->source = inet->inet_sport;
    uh->dest = fl4->fl4_dport;
    uh->len = htons(len);
    uh->check = 0;

    if (cork->gso_size) {
        const int hlen = skb_network_header_len(skb) +
                         sizeof(struct udphdr);

        if (hlen + cork->gso_size > cork->fragsize) {
            kfree_skb(skb);
            return -EINVAL;
        }
        if (datalen > cork->gso_size * UDP_MAX_SEGMENTS) {
            kfree_skb(skb);
            return -EINVAL;
        }
        if (sk->sk_no_check_tx) {
            kfree_skb(skb);
            return -EINVAL;
        }
        if (skb->ip_summed != CHECKSUM_PARTIAL || is_udplite ||
            dst_xfrm(skb_dst(skb))) {
            kfree_skb(skb);
            return -EIO;
        }

        if (datalen > cork->gso_size) {
            skb_shinfo(skb)->gso_size = cork->gso_size;
            skb_shinfo(skb)->gso_type = SKB_GSO_UDP_L4;
            skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(datalen,
                                                     cork->gso_size);
        }
        goto csum_partial;
    }

    if (sk->sk_no_check_tx) {			 /* UDP csum off */

        skb->ip_summed = CHECKSUM_NONE;
        goto send;

    } else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* UDP hardware csum */
        csum_partial:

        udp4_hwcsum(skb, fl4->saddr, fl4->daddr);
        goto send;

    } else
        csum = udp_csum(skb);

    /* add protocol-dependent pseudo-header */
    // 添加上伪首部, 并进行校验和的计算
    uh->check = csum_tcpudp_magic(fl4->saddr, fl4->daddr, len,sk->sk_protocol, csum);
    if (uh->check == 0)
        uh->check = CSUM_MANGLED_0;

    send:
    err = self_defined_path_validation_send_skb(sock_net(sk), skb, output_interface);
    if (err) {
        if (err == -ENOBUFS && !inet->recverr) {
            UDP_INC_STATS(sock_net(sk),
                          UDP_MIB_SNDBUFERRORS, is_udplite);
            err = 0;
        }
    } else
        UDP_INC_STATS(sock_net(sk),
                      UDP_MIB_OUTDATAGRAMS, is_udplite);
    return err;
}