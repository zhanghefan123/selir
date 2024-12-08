#include <linux/netfilter.h>
#include "tools/tools.h"
#include "api/test.h"
#include "hooks/network_layer/ipv4/ip_local_out/ip_local_out.h"
#include "hooks/network_layer/ipv4/ip_output/ip_output.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "structure/header/lir_header.h"
#include "structure/header/icing_header.h"

int pv_local_out(struct net* net, struct sock* sk, struct sk_buff* skb, struct RoutingCalcRes* rcr){
    return __pv_local_out(net, sk, skb, rcr);
}

int __pv_local_out(struct net* net, struct sock* sk, struct sk_buff* skb, struct RoutingCalcRes* rcr){
    if (LIR_VERSION_NUMBER == rcr->destination_info->path_validation_protocol){
        struct LiRHeader *pvh = lir_hdr(skb);
        pvh->tot_len = htons(skb->len);
        lir_send_check(pvh);
        skb->protocol = htons(ETH_P_IP);
        return pv_output(net, sk, skb, rcr->output_interface);
    } else if(ICING_VERSION_NUMBER == rcr->destination_info->path_validation_protocol){
        struct ICINGHeader* icing_header = icing_hdr(skb);
        icing_header->tot_len = htons(skb->len);
        icing_send_check(icing_header);
        skb->protocol = htons(ETH_P_IP);
        return pv_output(net, sk, skb, rcr->output_interface);
    } else {
        return 0;
    }
}