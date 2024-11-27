//
// Created by 张贺凡 on 2024/11/27.
//

#ifndef LOADABLE_KERNEL_MODULE_IP_SEND_SKB_H
#define LOADABLE_KERNEL_MODULE_IP_SEND_SKB_H
#include <net/ip.h>

int self_defined_ip_send_skb(struct net *net, struct sk_buff *skb);
#endif //LOADABLE_KERNEL_MODULE_IP_SEND_SKB_H
