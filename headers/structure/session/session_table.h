//
// Created by 张贺凡 on 2024/12/9.
//

#ifndef PATH_VALIDATION_MODULE_SESSION_TABLE_H
#define PATH_VALIDATION_MODULE_SESSION_TABLE_H

#include <net/ip.h>
#include "structure/header/opt_header.h"


// entry 相关代码
// -------------------------------------------------------
struct SessionTableEntry {
    struct SessionID session_id; // 会话 id
    int source;  // 源
    int path_length; // 路径长度
    int current_index; // 当前索引
    struct OptHop *path; // 完整的路径
    struct net_device* output_interface; // 出接口
    struct hlist_node pointer; // 指向的是下一个节点
};

struct SessionTableEntry *init_ste(struct SessionID* session_id,
                                   int source,
                                   int path_length,
                                   struct net_device *output_interface);

void free_ste(struct SessionTableEntry* ste);
// -------------------------------------------------------


// table 相关代码
// -------------------------------------------------------

struct HashBasedSessionTable {
    // 使用的桶的数量
    int bucket_count;
    // 哈希表
    struct hlist_head *bucket_array;
};

struct HashBasedSessionTable *init_hbst(int bucket_count);

int free_hbst(struct HashBasedSessionTable* hbst);

struct hlist_head* get_bucket_in_hbst(struct HashBasedSessionTable* hbst, struct SessionID session_id);

int session_entry_equal_judgement(struct SessionTableEntry* entry, struct SessionID session_id);
// -------------------------------------------------------


#endif //PATH_VALIDATION_MODULE_SESSION_TABLE_H
