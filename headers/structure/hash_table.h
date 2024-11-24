//
// Created by zhf on 2024/11/24.
//

#ifndef LOADABLE_KERNEL_MODULE_HASH_TABLE_H
#define LOADABLE_KERNEL_MODULE_HASH_TABLE_H
#include <net/ip.h>
struct hlist_head* initialize_hash_table(int bucket_count);
#endif //LOADABLE_KERNEL_MODULE_HASH_TABLE_H
