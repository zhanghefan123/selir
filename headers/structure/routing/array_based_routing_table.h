//
// Created by 张贺凡 on 2024/11/26.
//

#ifndef LOADABLE_KERNEL_MODULE_ARRAY_BASED_ROUTING_TABLE_H
#define LOADABLE_KERNEL_MODULE_ARRAY_BASED_ROUTING_TABLE_H

#include "structure/routing/routing_table_entry.h"
#include "structure/routing/routing_calc_res.h"
#include "structure/routing/destination_info.h"
#include "structure/crypto/bloom_filter.h"
#include "tools/tools.h"

// 3.1 基于数组的路由表
struct ArrayBasedRoutingTable {
    // 路由条数
    int number_of_routes;
    // 所有的路由条目
    struct RoutingTableEntry **routes;
};

struct ArrayBasedRoutingTable *init_abrt(int number_of_routes);

void free_abrt(struct ArrayBasedRoutingTable *abrt);

struct RoutingTableEntry *find_sre_in_abrt(struct ArrayBasedRoutingTable *abrt, int destination);

void add_entry_to_abrt(struct ArrayBasedRoutingTable* abrt, struct RoutingTableEntry* rte);

struct RoutingCalcRes *construct_rcr_with_dest_info_under_abrt(struct ArrayBasedRoutingTable *abrt,
                                                               struct DestinationInfo *destination_info,
                                                               int bf_effective_bytes);

#endif //LOADABLE_KERNEL_MODULE_ARRAY_BASED_ROUTING_TABLE_H
