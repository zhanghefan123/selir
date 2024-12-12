#include "tools/tools.h"
#include "api/test.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include <net/inet_ecn.h>

asmlinkage int(*orig_ip_rcv)(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);

asmlinkage int hook_ip_rcv(struct sk_buff *skb,
                           struct net_device *dev,
                           struct packet_type *pt,
                           struct net_device *orig_dev) {
    int version_number = ip_hdr(skb)->version;
    if (IP_VERSION_NUMBER == version_number){
        return orig_ip_rcv(skb, dev, pt, orig_dev);
    } else if (LIR_VERSION_NUMBER == version_number) {
        // 实验所需, 先不打印
        // LOG_WITH_PREFIX("receive lir packet");
        return lir_rcv(skb, dev, pt, orig_dev);
    } else if (ICING_VERSION_NUMBER == version_number) {
        // 实验所需, 先不打印
        // LOG_WITH_PREFIX("receive icing packet");
        return icing_rcv(skb, dev, pt, orig_dev);
    } else if ((OPT_ESTABLISH_VERSION_NUMBER == version_number) || (OPT_DATA_VERSION_NUMBER == version_number)) {
        // 实验所需, 先不打印
        // LOG_WITH_PREFIX("receive opt packet");
        return opt_rcv(skb, dev, pt, orig_dev);
    } else if(SELIR_VERSION_NUMBER == version_number) {
        // 实验所需, 先不打印
        // LOG_WITH_PREFIX("receive selir packet");
        return selir_rcv(skb, dev, pt, orig_dev);
    } else {
        LOG_WITH_PREFIX("unknown packet type");
        return -EINVAL;
    }
}

void add_ip_rcv_to_hook(void){
    hooks[number_of_hook].name = "ip_rcv";
    hooks[number_of_hook].function = hook_ip_rcv;
    hooks[number_of_hook].original = &orig_ip_rcv;
    number_of_hook += 1;
}