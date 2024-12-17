//
// Created by 张贺凡 on 2024/12/9.
//

#ifndef PATH_VALIDATION_MODULE_SESSION_TABLE_H
#define PATH_VALIDATION_MODULE_SESSION_TABLE_H

#include <net/ip.h>
#include "structure/header/opt_header.h"


// entry 相关代码
// -------------------------------------------------------
// A ---- 1 ----> B ---- 2 ----> C
// OptHop[nodeid = B, linkid = 2] OptHop[nodeid = C, linkid = 0]
struct SessionTableEntry {
    struct SessionID session_id; // 会话 id
    int encrypt_len; // 所有的上游节点
    int *encrypt_order; // hmac 的次序, 在 C 节点, 顺序为 KC --> KB
    struct net_device *output_interface; // 出接口
    int previous_node; // 进行前驱节点的记录
    unsigned char **session_keys; // 前驱节点的 key, 包括自身的 key
    unsigned char *session_key; // 自己的 session_key
    int path_length; // 路径的长度
    struct OptHop *opt_hops; // 路径
    struct hlist_node pointer; // 指向的是下一个节点
};

struct SessionTableEntry *init_ste_in_dest(struct SessionID *session_id,
                                           int encrypt_count,
                                           int previous_node,
                                           int current_path_index,
                                           unsigned char* session_key);

struct SessionTableEntry *init_ste_in_intermediate(struct SessionID *sessionId,
                                                   struct net_device *output_interface,
                                                   unsigned char* session_key,
                                                   int previous_node);

void free_ste(struct SessionTableEntry *ste);
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

int free_hbst(struct HashBasedSessionTable *hbst);

struct hlist_head *get_bucket_in_hbst(struct HashBasedSessionTable *hbst, struct SessionID session_id);

int session_entry_equal_judgement(struct SessionTableEntry *entry, struct SessionID session_id);

int add_entry_to_hbst(struct HashBasedSessionTable *hbst, struct SessionTableEntry *ste);

struct SessionTableEntry *find_ste_in_hbst(struct HashBasedSessionTable *hbst, struct SessionID *session_id);
// -------------------------------------------------------


#endif //PATH_VALIDATION_MODULE_SESSION_TABLE_H
