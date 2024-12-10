#include "tools/tools.h"
#include "structure/session/session_table.h"


/**
 * 初始化会话表项
 * @param session_id 会话 id
 * @param encrypt_count
 * @param output_interface 出接口
 * @return
 */
struct SessionTableEntry *init_ste_in_dest(struct SessionID* session_id,
                                           int encrypt_count) {
    struct SessionTableEntry *ste = (struct SessionTableEntry *) kmalloc(sizeof(struct SessionTableEntry), GFP_KERNEL);
    ste->session_id.first_part = session_id->first_part;
    ste->session_id.second_part = session_id->second_part;
    ste->encrypt_len = encrypt_count;
    ste->encrypt_order = (int*)(kmalloc(sizeof(int) * encrypt_count, GFP_KERNEL));
    ste->output_interface = NULL;
    return ste;
}

struct SessionTableEntry *init_ste_in_intermediate(struct SessionID *session_id, struct net_device *output_interface){
    struct SessionTableEntry* ste = (struct SessionTableEntry*) kmalloc(sizeof(struct SessionTableEntry), GFP_KERNEL);
    ste->session_id.first_part = session_id->first_part;
    ste->session_id.second_part = session_id->second_part;
    ste->encrypt_len = 0;
    ste->encrypt_order = NULL;
    ste->output_interface = output_interface;
    return ste;
}

/**
 * 进行会话表条的释放
 * @param ste 会话表的条目
 */
void free_ste(struct SessionTableEntry* ste) {
    if (NULL != ste){
        if(NULL != ste->encrypt_order) {
            kfree(ste->encrypt_order);
        }
    }
}

/**
 * 初始化基于哈希的会话表
 * @param bucket_count 桶的数量
 * @return
 */
struct HashBasedSessionTable *init_hbst(int bucket_count) {
    int index;
    // 链地址发的左侧竖直的列表
    struct hlist_head* head_pointer_list = NULL;
    head_pointer_list = (struct hlist_head *) kmalloc(sizeof(struct hlist_head) * bucket_count, GFP_KERNEL);
    if (NULL == head_pointer_list) {
        LOG_WITH_PREFIX("alloc memory for head_pointer_list failed!");
    }
    // 初始化表头
    for (index = 0; index < bucket_count; index++) {
        INIT_HLIST_HEAD(&head_pointer_list[index]);
    }
    // 创建 hash based session table
    struct HashBasedSessionTable *hbst = (struct HashBasedSessionTable *) kmalloc(sizeof(struct HashBasedSessionTable),
                                                                                  GFP_KERNEL);
    hbst->bucket_count = bucket_count;
    hbst->bucket_array = head_pointer_list;
    return hbst;
}

/**
 * 进行基于哈希的会话表的释放
 * @param hbst 基于哈希的会话表
 * @return
 */
int free_hbst(struct HashBasedSessionTable* hbst){
    // 这里首先判断要进行 free 的 hbrt 是否为 NULL
    if(NULL != hbst){
        int index;
        struct hlist_head *hash_bucket = NULL;
        struct SessionTableEntry *current_entry = NULL;
        struct hlist_node *next;
        printk(KERN_EMERG "hash bucket count: %d \n", hbst->bucket_count);
        for (index = 0; index < hbst->bucket_count; index++) {
            hash_bucket = &(hbst->bucket_array[index]);
            // 每一个 hash_bucket 都被初始化过了，所以不能为NULL
            if (NULL == hash_bucket) {
                LOG_WITH_PREFIX("hash bucket is null");
                return -1;
            }
            hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
                LOG_WITH_PREFIX("hello");
                if(NULL != current_entry){
                    hlist_del(&current_entry->pointer);
                    free_ste(current_entry);
                }
            }
        }
        // 清空 head_pointer_list 引入的 memory 开销
        if (NULL != hbst->bucket_array){
            kfree(hbst->bucket_array);
        }
        // 释放 hbrt
        kfree(hbst);
        LOG_WITH_PREFIX("delete hash based session table successfully!");
    } else {
        LOG_WITH_PREFIX("hash based session table is NULL");
    }
    return 0;
}

/**
 * 基于哈希值进行 bucket 的获取
 * @param hbst 基于哈希的会话表
 * @param session_id 会话 id
 * @return
 */
struct hlist_head* get_bucket_in_hbst(struct HashBasedSessionTable* hbst, struct SessionID session_id){
    u32 index_of_bucket;
    index_of_bucket = session_id.second_part % hbst->bucket_count;
    return &hbst->bucket_array[index_of_bucket];
}

/**
 * 判断两个会话表项是否相等
 * @param entry 会话表项
 * @param session_id 会话 id
 * @return
 */
int session_entry_equal_judgement(struct SessionTableEntry* entry, struct SessionID session_id) {
    if(NULL == entry){
        return 1;
    }
    // 如果两个表项的 session_id 相同即可
    if((entry->session_id.first_part == session_id.first_part) && (entry->session_id.second_part == session_id.second_part)){
        return 0;
    } else {
        return 1;
    }
}

/**
 * 将会话表项添加到基于哈希的会话表之中
 * @param hbst 基于哈希的会话表
 * @param ste 会话表项
 * @return
 */
int add_entry_to_hbst(struct HashBasedSessionTable* hbst, struct SessionTableEntry* ste){
    struct hlist_head* hash_bucket = NULL;
    struct SessionTableEntry* current_ste = NULL;
    struct hlist_node* next = NULL;
    // 首先找到对应的应该存放的 bucket
    hash_bucket = get_bucket_in_hbst(hbst, ste->session_id);
    if (NULL == hash_bucket) {
        // 找不到 hash_bucket
        LOG_WITH_PREFIX("cannot find hash bucket");
        free_ste(ste);
        return -1;
    }
    // 检查是否出现了相同的会话表项
    hlist_for_each_entry_safe(current_ste, next, hash_bucket, pointer){
        if(0 == session_entry_equal_judgement(current_ste, ste->session_id)) {
            LOG_WITH_PREFIX("already exists session entry");
            free_ste(ste);
        }
    }
    // 这个时候说明我们真的需要创建一个自己的 node
    INIT_HLIST_NODE(&ste->pointer);
    hlist_add_head(&ste->pointer, hash_bucket);
    return 0;
}