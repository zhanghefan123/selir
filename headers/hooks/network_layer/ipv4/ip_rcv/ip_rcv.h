//
// Created by 张贺凡 on 2024/12/3.
//

#ifndef LOADABLE_KERNEL_MODULE_IP_RCV_H
#define LOADABLE_KERNEL_MODULE_IP_RCV_H
#include <net/ip.h>
#include "api/ftrace_hook_api.h"
int path_validation_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type *pt, struct net_device* orig_dev);
int self_defined_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);
void add_ip_rcv_to_hook(void);
struct sk_buff* path_validation_rcv_core(struct sk_buff* skb, struct net* net);
extern struct ftrace_hook hooks[MAXIMUM_SUPPORTED_HOOK_FUNCTIONS];
extern int number_of_hook;
#endif //LOADABLE_KERNEL_MODULE_IP_RCV_H
