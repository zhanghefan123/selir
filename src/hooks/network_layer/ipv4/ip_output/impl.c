#include <linux/bpf-cgroup.h>
#include "hooks/network_layer/ipv4/ip_output/ip_output.h"

int pv_output(struct net *net, struct sock *sk, struct sk_buff *skb, struct net_device* output_interface){
    struct net_device *dev = output_interface;

    IP_UPD_PO_STATS(net, IPSTATS_MIB_OUT, skb->len);

    skb->dev = dev;
    skb->protocol = htons(ETH_P_IP);

    return pv_finish_output(net, sk, skb, output_interface);
}

int pv_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb, struct net_device* output_interface) {
    int ret;

    ret = BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb);
    switch (ret) {
        case NET_XMIT_SUCCESS:
            return pv__ip_finish_output(net, sk, skb, output_interface);
        case NET_XMIT_CN:
            return pv__ip_finish_output(net, sk, skb, output_interface) ?: ret;
        default:
            kfree_skb_reason(skb, SKB_DROP_REASON_BPF_CGROUP_EGRESS);
            return ret;
    }
}

int pv__ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb, struct net_device* output_interface) {
    return pv_finish_output2(net, sk, skb, output_interface);
}


int pv_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb, struct net_device* output_interface) {
    struct net_device *dev = output_interface;
    unsigned int hh_len = LL_RESERVED_SPACE(dev);
    struct neighbour *neigh;
    bool is_v6gw = false;

    if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
        skb = skb_expand_head(skb, hh_len);
        if (!skb)
            return -ENOMEM;
    }

    rcu_read_lock_bh();
    neigh = ip_neigh_gw4(output_interface, INADDR_BROADCAST);
    if (!IS_ERR(neigh)) {
        int res;

        sock_confirm_neigh(skb, neigh);
        /* if crossing protocols, can not use the cached header */
        res = neigh_output(neigh, skb, is_v6gw);
        rcu_read_unlock_bh();
        return res;
    }
    rcu_read_unlock_bh();

    net_dbg_ratelimited("%s: No header cache and no neighbour!\n",
                        __func__);
    kfree_skb_reason(skb, SKB_DROP_REASON_NEIGH_CREATEFAIL);
    return -EINVAL;
}
