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
    struct hlist_node pointer; // 指向的是下一个节点
};

struct SessionTableEntry *init_ste_in_dest(struct SessionID *session_id, int encrypt_count);

struct SessionTableEntry *init_ste_in_intermediate(struct SessionID *sessionId,
                                                   struct net_device *output_interface);

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
// -------------------------------------------------------


#endif //PATH_VALIDATION_MODULE_SESSION_TABLE_H
