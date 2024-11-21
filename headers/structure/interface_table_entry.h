//
// Created by zhf on 2024/11/21.
//

#ifndef LOADABLE_KERNEL_MODULE_INTERFACE_TABNLE_ENTRY_H
#define LOADABLE_KERNEL_MODULE_INTERFACE_TABNLE_ENTRY_H
#include <net/ip.h>

struct InterfaceTableEntry {
    int link_identifier; // 链路标识
    struct net_device *interface; // 对应的接口
};

#endif //LOADABLE_KERNEL_MODULE_INTERFACE_TABNLE_ENTRY_H
