//
// Created by 张贺凡 on 2024/11/27.
//

#ifndef LOADABLE_KERNEL_MODULE_IP_APPEND_DATA_H
#define LOADABLE_KERNEL_MODULE_IP_APPEND_DATA_H

#include <net/ip.h>

bool resolve_ip_append_data_inner_functions_address(void);

int self_defined_ip_append_data(struct sock *sk, struct flowi4 *fl4,
                                int getfrag(void *from, char *to, int offset, int len,
                                            int odd, struct sk_buff *skb),
                                void *from, int length, int transhdrlen,
                                struct ipcm_cookie *ipc, struct rtable **rtp,
                                unsigned int flags);

int self_defined__ip_append_data(struct sock *sk,
                                 struct flowi4 *fl4,
                                 struct sk_buff_head *queue,
                                 struct inet_cork *cork,
                                 struct page_frag *pfrag,
                                 int getfrag(void *from, char *to, int offset,
                                             int len, int odd, struct sk_buff *skb),
                                 void *from, int length, int transhdrlen,
                                 unsigned int flags);

#endif //LOADABLE_KERNEL_MODULE_IP_APPEND_DATA_H
