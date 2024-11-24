//
// Created by zhf on 2024/11/24.
//

#ifndef LOADABLE_KERNEL_MODULE_IP_MAKE_SKB_H
#define LOADABLE_KERNEL_MODULE_IP_MAKE_SKB_H
#include <net/ip.h>
int path_validation_setup_cork(struct sock *sk, struct inet_cork *cork, struct ipcm_cookie *ipc, struct rtable **rtp);
struct sk_buff *path_validation_make_skb(struct sock *sk,
                        struct flowi4 *fl4,
                        int getfrag(void *from, char *to, int offset,
                                    int len, int odd, struct sk_buff *skb),
                        void *from, int length, int transhdrlen,
                        struct ipcm_cookie *ipc, struct rtable **rtp,
                        struct inet_cork *cork, unsigned int flags);
#endif //LOADABLE_KERNEL_MODULE_IP_MAKE_SKB_H
