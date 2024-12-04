#include <linux/netfilter.h>
#include "tools/tools.h"
#include "hooks/network_layer/ipv4/ip_local_out/ip_local_out.h"
#include "hooks/network_layer/ipv4/ip_output/ip_output.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "structure/path_validation_header.h"

int pv_local_out(struct net* net, struct sock* sk, struct sk_buff* skb, struct net_device* output_interface){
    return __pv_local_out(net, sk, skb, output_interface);
}

int __pv_local_out(struct net* net, struct sock* sk, struct sk_buff* skb, struct net_device* output_interface){
    struct PathValidationHeader *pvh = pvh_hdr(skb);
    pvh->tot_len = htons(skb->len);
    pv_send_check(pvh);
    skb->protocol = htons(ETH_P_IP);
    return pv_output(net, sk, skb, output_interface);
}