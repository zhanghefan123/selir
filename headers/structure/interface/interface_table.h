//
// Created by zhf on 2024/11/21.
//

#ifndef LOADABLE_KERNEL_MODULE_INTERFACE_TABNLE_ENTRY_H
#define LOADABLE_KERNEL_MODULE_INTERFACE_TABNLE_ENTRY_H
#include <net/ip.h>

// 1. 接口表项相关内容
// ----------------------------------------------------------------------------------------------
struct InterfaceTableEntry {
    int link_identifier; // 链路标识
    struct net_device *interface; // 对应的接口
    int index; // 在接口表之中的索引
    unsigned char* bitset; // 将这个标识插入之后的布隆过滤器
};
// ----------------------------------------------------------------------------------------------

// 2. 基于数组的接口表相关内容
// ----------------------------------------------------------------------------------------------
struct ArrayBasedInterfaceTable{
    // 总的接口的数量
    int number_of_interfaces;
    // 所有的接口
    struct InterfaceTableEntry* interfaces;
};
struct ArrayBasedInterfaceTable* initialize_array_based_interface_table(int number_of_interfaces);
void free_array_based_interface_table(struct ArrayBasedInterfaceTable* abit);
struct InterfaceTableEntry* find_intf_in_abit(struct ArrayBasedInterfaceTable* abit, int link_identifier);
// ----------------------------------------------------------------------------------------------

#endif //LOADABLE_KERNEL_MODULE_INTERFACE_TABNLE_ENTRY_H
