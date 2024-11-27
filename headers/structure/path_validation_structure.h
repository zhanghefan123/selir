//
// Created by zhf on 2024/11/21.
//

#ifndef LOADABLE_KERNEL_MODULE_PATH_VALIDATION_STRUCTURE_H
#define LOADABLE_KERNEL_MODULE_PATH_VALIDATION_STRUCTURE_H

#include "structure/crypto/bloom_filter.h"
#include "structure/interface/interface_table.h"
#include "structure/routing/array_based_routing_table.h"
#include "structure/routing/hash_based_routing_table.h"

struct PathValidationStructure {
    // 当前节点的 id
    int node_id;
    // 路由表的类型
    int routing_table_type;
    // 路由的类型 (unicast/multicast)
    int routing_type;
    // 基于数组的路由表
    struct ArrayBasedRoutingTable *abrt;
    // 基于哈希的路由表
    struct HashBasedRoutingTable *hbrt;
    // 基于数组的接口表
    struct ArrayBasedInterfaceTable *abit;
    // 布隆过滤器
    struct BloomFilter *bloom_filter;

};

struct PathValidationStructure *initialize_pvs(void);

void free_pvs(struct PathValidationStructure *pvs);

void initialize_routing_and_forwarding_table(struct PathValidationStructure *pvs,
                                             int routing_table_type,
                                             int routing_type,
                                             int number_of_routes_or_buckets,
                                             int number_of_interfaces);

#endif //LOADABLE_KERNEL_MODULE_PATH_VALIDATION_STRUCTURE_H
