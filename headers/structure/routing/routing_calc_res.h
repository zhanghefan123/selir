//
// Created by 张贺凡 on 2024/11/26.
//

#ifndef LOADABLE_KERNEL_MODULE_ROUTING_CALC_RES_H
#define LOADABLE_KERNEL_MODULE_ROUTING_CALC_RES_H

#include <net/ip.h>
#include "structure/crypto/bloom_filter.h"
#include "structure/routing/destination_info.h"
#include "structure/path_validation_structure.h"

// 1. 路由计算结果
struct RoutingCalcRes {
    int source;
    unsigned char *bitset; // 结果布隆过滤器
    struct net_device *output_interface; // 出接口
    struct DestinationInfo *destination_info; // 目的信息
    struct PathValidationStructure *pvs;  // 路径验证信息
};

// 2. 初始化计算结果
struct RoutingCalcRes *init_rcr(int source,
                                struct DestinationInfo *destination_info,
                                struct PathValidationStructure* pvs);

// 3. 释放路由计算结果
void free_rcr(struct RoutingCalcRes *route_calculation_result);

#endif //LOADABLE_KERNEL_MODULE_ROUTING_CALC_RES_H
