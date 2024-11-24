//
// Created by zhf on 2024/11/21.
//

#ifndef LOADABLE_KERNEL_MODULE_SOURCE_ROUTING_TABLE_H
#define LOADABLE_KERNEL_MODULE_SOURCE_ROUTING_TABLE_H

#include <net/ip.h>
#include "structure/destination_info.h"

// 1.路由表项相关内容
// ----------------------------------------------------------------------------------------------
// 1.1 路由表项
struct SourceRoutingTableEntry {
    int source_id;       // 源节点的 id
    int destination_id;  // 目的节点的 id
    int path_length;  // 路径的长度
    int *node_ids;       // 节点序列
    unsigned char *bitset; // 插入 link_identifiers 所对应的 bitset
    int *link_identifiers; // 到目的节点的链路表示序列
    struct net_device *output_interface; // 出接口所对应的接口表项
    u32 effective_bytes; // bitset 所对应的有效的字节数
    struct hlist_node pointer; // 指针指向的是下一个路由条目
};

// 1.2 初始化源路由表项
struct SourceRoutingTableEntry *init_source_routing_table_entry(int effective_bytes);

// 1.3 释放源路由表项
void free_source_routing_table_entry(struct SourceRoutingTableEntry *source_routing_table_entry);
// ----------------------------------------------------------------------------------------------

// 2. 基于数组的路由表的相关内容 (适用于单播)
// ----------------------------------------------------------------------------------------------

#define ARRAY_BASED_ROUTING_TABLE_TYPE 1
#define HASH_BASED_ROUTING_TABLE_TYPE 2

// 2.1 基于数组的路由表
struct ArrayBasedRoutingTable {
    // 路由条数
    int number_of_routes;
    // 所有的路由条目
    struct SourceRoutingTableEntry *routes;
};

struct ArrayBasedRoutingTable *initialize_array_based_routing_table(int number_of_routes);

void free_array_based_routing_table(struct ArrayBasedRoutingTable *abrt);
// ----------------------------------------------------------------------------------------------

// 3. 基于哈希表的路由表的相关内容
// ----------------------------------------------------------------------------------------------
struct HashBasedRoutingTable {
    // 使用的桶的数量
    int bucket_count;
    // 哈希表
    struct hlist_head *bucket_array;
};

struct HashBasedRoutingTable* initialize_hbrt(int bucket_count);
struct hlist_head *get_bucket_in_hbrt(struct HashBasedRoutingTable *hbrt,
                                                          int source_id,
                                                          int destination_id);
int routing_entry_equal_judgement(struct SourceRoutingTableEntry *entry, int source_id, int destination_id);
int add_entry_to_hbrt(struct HashBasedRoutingTable *hbrt, struct SourceRoutingTableEntry *routing_table_entry);
// ----------------------------------------------------------------------------------------------

#endif //LOADABLE_KERNEL_MODULE_SOURCE_ROUTING_TABLE_H
