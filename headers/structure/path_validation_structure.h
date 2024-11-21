//
// Created by zhf on 2024/11/21.
//

#ifndef LOADABLE_KERNEL_MODULE_PATH_VALIDATION_STRUCTURE_H
#define LOADABLE_KERNEL_MODULE_PATH_VALIDATION_STRUCTURE_H
#include "structure/bloom_filter.h"
#include "structure/interface_table_entry.h"
#include "structure/source_routing_table_entry.h"

struct PathValidationStructure {
    // 路由条数
    int number_of_routes;
    // 路由表
    struct SourceRoutingTableEntry* source_routing_table;
    // 接口数
    int number_of_interfaces;
    // 接口表
    struct InterfaceTableEntry* interface_table;
    // 布隆过滤器
    struct BloomFilter* bloom_filter;

};

struct PathValidationStructure* initialize_path_validation_structure(int number_of_routes, int number_of_interfaces);

void free_path_validation_structure(struct PathValidationStructure* path_validation_structure);

#endif //LOADABLE_KERNEL_MODULE_PATH_VALIDATION_STRUCTURE_H
