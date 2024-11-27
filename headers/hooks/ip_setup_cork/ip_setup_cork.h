//
// Created by 张贺凡 on 2024/11/27.
//

#ifndef LOADABLE_KERNEL_MODULE_IP_SETUP_CORK_H
#define LOADABLE_KERNEL_MODULE_IP_SETUP_CORK_H
#include <net/ip.h>
int self_defined_ip_setup_cork(struct sock *sk, struct inet_cork *cork, struct ipcm_cookie *ipc, struct rtable **rtp);
#endif //LOADABLE_KERNEL_MODULE_IP_SETUP_CORK_H
