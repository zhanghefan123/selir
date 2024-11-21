//
// Created by zhf on 2024/11/21.
//

#ifndef LOADABLE_KERNEL_MODULE_NETLINK_HANDLER_H
#define LOADABLE_KERNEL_MODULE_NETLINK_HANDLER_H
#include <net/sock.h>
#include <net/genetlink.h>
int netlink_test_handler(struct sk_buff* request, struct genl_info* info);
#endif //LOADABLE_KERNEL_MODULE_NETLINK_HANDLER_H
