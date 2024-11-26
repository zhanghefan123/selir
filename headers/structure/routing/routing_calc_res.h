//
// Created by 张贺凡 on 2024/11/26.
//

#ifndef LOADABLE_KERNEL_MODULE_ROUTING_CALC_RES_H
#define LOADABLE_KERNEL_MODULE_ROUTING_CALC_RES_H

#include <net/ip.h>
#include "structure/crypto/bloom_filter.h"

// 1. 路由计算结果
struct RoutingCalcRes {
    unsigned char *bitsets; // 结果布隆过滤器
    struct net_device **output_interfaces; // 出接口
    struct DestinationInfo *destination_info; // 目的信息
};

// 2. 初始化计算结果
struct RoutingCalcRes *init_rcr(struct DestinationInfo *destination_info,
                                int bf_effective_bytes,
                                int number_of_output_interfaces);

// 3. 释放路由计算结果
void free_rcr(struct RoutingCalcRes *route_calculation_result);

#endif //LOADABLE_KERNEL_MODULE_ROUTING_CALC_RES_H
