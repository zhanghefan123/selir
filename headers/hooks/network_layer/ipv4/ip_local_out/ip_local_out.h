//
// Created by 张贺凡 on 2024/12/3.
//

#ifndef LOADABLE_KERNEL_MODULE_IP_LOCAL_OUT_H
#define LOADABLE_KERNEL_MODULE_IP_LOCAL_OUT_H
#include <net/ip.h>
int pv_local_out(struct net* net, struct sock* sk, struct sk_buff* skb, struct net_device* output_interface);
int __pv_local_out(struct net* net, struct sock* sk, struct sk_buff* skb, struct net_device* output_interface);
#endif //LOADABLE_KERNEL_MODULE_IP_LOCAL_OUT_H
