#include <net/ip.h>

int pv_packet_forward(struct sk_buff* skb, struct net_device* output_interface, struct net* current_net_namespace);