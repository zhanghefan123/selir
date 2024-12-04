#include "tools/tools.h"
#include "api/test.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"

asmlinkage int(*orig_ip_rcv)(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);

asmlinkage int hook_ip_rcv(struct sk_buff *skb,
                           struct net_device *dev,
                           struct packet_type *pt,
                           struct net_device *orig_dev) {
    int network_type = resolve_network_type_from_skb(skb);
    if(IP_NETWORK_TYPE == network_type){
        return orig_ip_rcv(skb, dev, pt, orig_dev);
    } else {
        return path_validation_rcv(skb, dev, pt, orig_dev);
    }
}

void add_ip_rcv_to_hook(void){
    hooks[number_of_hook].name = "ip_rcv";
    hooks[number_of_hook].function = hook_ip_rcv;
    hooks[number_of_hook].original = &orig_ip_rcv;
    number_of_hook += 1;
}