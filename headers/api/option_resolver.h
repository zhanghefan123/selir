//
// Created by zhf on 2024/11/24.
//

#ifndef LOADABLE_KERNEL_MODULE_OPTION_RESOLVER_H
#define LOADABLE_KERNEL_MODULE_OPTION_RESOLVER_H
#include "structure/routing/destination_info.h"
#define OPTION_START_INDEX 2
// 这里的起始 index 为 2 的原因是, 第一个字节是 type, 第二个字节是 length
struct DestinationInfo* resolve_option_for_destination_info(struct ip_options_rcu* opt);
#endif //LOADABLE_KERNEL_MODULE_OPTION_RESOLVER_H
