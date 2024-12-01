//
// Created by zhf on 2024/11/24.
//

#ifndef LOADABLE_KERNEL_MODULE_IP_MAKE_SKB_H
#define LOADABLE_KERNEL_MODULE_IP_MAKE_SKB_H

#include <net/ip.h>
#include "structure/routing/routing_calc_res.h"

struct sk_buff *self_defined_ip_make_skb(struct sock *sk,
                                         struct flowi4 *fl4,
                                         int getfrag(void *from, char *to, int offset,
                                                     int len, int odd, struct sk_buff *skb),
                                         void *from, int length, int transhdrlen,
                                         struct ipcm_cookie *ipc,
                                         struct inet_cork *cork, unsigned int flags, struct RoutingCalcRes* rcr);



struct sk_buff *self_defined__ip_make_skb(struct sock *sk,
                                          struct flowi4 *fl4,
                                          struct sk_buff_head *queue,
                                          struct inet_cork *cork,
                                          struct RoutingCalcRes* rcr);

bool resolve_ip_make_skb_inner_functions_address(void);

#endif //LOADABLE_KERNEL_MODULE_IP_MAKE_SKB_H
