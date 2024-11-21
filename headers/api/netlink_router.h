//
// Created by zhf on 2024/11/21.
//

#ifndef LOADABLE_KERNEL_MODULE_NETLINK_SERVER_H
#define LOADABLE_KERNEL_MODULE_NETLINK_SERVER_H
#include <net/genetlink.h>

void netlink_server_init(void); // netlink server 初始化

void netlink_server_exit(void); // netlink server 退出


/**
 * 消息的类型，用户空间同样需要定义相应的代码
 */
enum {
    EXMPL_NLA_UNSPEC, // 未指定
    EXMPL_NLA_DATA, // 数据部分
    EXMPL_NLA_LEN, // 数据的长度
    EXMPL_NLA_MAX,  // 最大的数量
};

/**
 * 命令的类型, 用户空间同样需要定义相应的命令类型
 */

enum {
    CMD_UNSPEC,
    CMD_ECHO, // 1. 用来进行消息回显的
};

#define VERSION_NR 1
extern struct genl_family exmpl_genl_family;
extern const struct genl_ops exmpl_gnl_ops_echo[];
extern struct nla_policy attr_type_mapping[EXMPL_NLA_MAX];

#endif //LOADABLE_KERNEL_MODULE_NETLINK_SERVER_H
