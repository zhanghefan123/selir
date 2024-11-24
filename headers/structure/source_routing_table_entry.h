//
// Created by zhf on 2024/11/21.
//

#ifndef LOADABLE_KERNEL_MODULE_SOURCE_ROUTING_TABLE_ENTRY_H
#define LOADABLE_KERNEL_MODULE_SOURCE_ROUTING_TABLE_ENTRY_H
#include <net/ip.h>

// 路由表项
struct SourceRoutingTableEntry {
    int source_id;       // 源节点的 id
    int destination_id;  // 目的节点的 id
    int path_length;  // 路径的长度
    int *node_ids;       // 节点序列
    unsigned char *bitset; // 插入 link_identifiers 所对应的 bitset
    int *link_identifiers; // 到目的节点的链路表示序列
    struct net_device* output_interface; // 出接口所对应的接口表项
    u32 effective_bytes; // bitset 所对应的有效的字节数
};

// 初始化源路由表项
struct SourceRoutingTableEntry* init_source_routing_table_entry(int effective_bytes);

// 释放源路由表项
void free_source_routing_table_entry(struct SourceRoutingTableEntry* source_routing_table_entry);

#endif //LOADABLE_KERNEL_MODULE_SOURCE_ROUTING_TABLE_ENTRY_H
