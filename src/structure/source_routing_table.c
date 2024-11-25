#include "tools/tools.h"
#include "structure/source_routing_table.h"

/**
 * 进行源路由表项的创建, 分配内存
 * @param bitset_length bitarray 的长度 (unsigned long 为单位)
 * @return
 */
struct SourceRoutingTableEntry *init_source_routing_table_entry(int effective_bytes) {
    // 为 source_routing_table_entry 分配内存
    struct SourceRoutingTableEntry *source_routing_table_entry = (struct SourceRoutingTableEntry *) kmalloc(
            sizeof(struct SourceRoutingTableEntry), GFP_KERNEL);
    // 为 bitset 分配内存
    source_routing_table_entry->bitset = (unsigned char *) kmalloc(sizeof(unsigned char) * effective_bytes, GFP_KERNEL);
    // 设置有效字节数
    source_routing_table_entry->effective_bytes = effective_bytes;
    // 返回结果
    return source_routing_table_entry;
}

/**
 * 进行源路由表项的创建
 * @param source_routing_table_entry
 */
void free_source_routing_table_entry(struct SourceRoutingTableEntry *source_routing_table_entry) {
    if (NULL != source_routing_table_entry) {
        if (NULL != source_routing_table_entry->node_ids) {
            kfree(source_routing_table_entry->node_ids);
        }
        if (NULL != source_routing_table_entry->bitset) {
            kfree(source_routing_table_entry->bitset);
        }
        if (NULL != source_routing_table_entry->link_identifiers) {
            kfree(source_routing_table_entry->link_identifiers);
        }
    }
}

/**
 * 进行基于数组的路由表的创建
 * @param number_of_routes 路由的条数
 * @return
 */
struct ArrayBasedRoutingTable *initialize_array_based_routing_table(int number_of_routes) {
    // 分配内存
    struct ArrayBasedRoutingTable *abrt = (struct ArrayBasedRoutingTable *) kmalloc(
            sizeof(struct ArrayBasedRoutingTable), GFP_KERNEL);
    // 设置路由条数
    abrt->number_of_routes = number_of_routes;
    // 为路由表分配内存
    abrt->routes = (struct SourceRoutingTableEntry *) kmalloc(sizeof(struct SourceRoutingTableEntry) * number_of_routes,
                                                              GFP_KERNEL);
    // 进行创建结果的返回
    return abrt;
}

/**
 * 进行基于数组的路由表的释放
 * @param abrt
 */
void free_array_based_routing_table(struct ArrayBasedRoutingTable *abrt) {
    int index;
    if (NULL != abrt) {
        if (NULL != abrt->routes) {
            for (index = 0; index < abrt->number_of_routes; index++) {
                free_source_routing_table_entry(&(abrt->routes[index]));
            }
            kfree(abrt->routes);
        }
        kfree(abrt);
        abrt = NULL;
    }
    LOG_WITH_PREFIX("delete array based routing table successfully!")
}


struct HashBasedRoutingTable *initialize_hbrt(int bucket_count) {
    int index;
    // 链地址法的左侧竖直列表
    struct hlist_head *head_pointer_list = NULL;
    head_pointer_list = (struct hlist_head *) kmalloc(sizeof(struct hlist_head) * bucket_count, GFP_KERNEL);
    if (NULL == head_pointer_list) {
        LOG_WITH_PREFIX("alloc memory for head_pointer_list failed!");
    }
    // 初始化表头
    for (index = 0; index < bucket_count; index++) {
        INIT_HLIST_HEAD(&head_pointer_lisgit t[index]);
    }
    // 创建 hash based routing table
    struct HashBasedRoutingTable *hbrt = (struct HashBasedRoutingTable *) kmalloc(sizeof(struct HashBasedRoutingTable),
                                                                                  GFP_KERNEL);
    hbrt->bucket_count = bucket_count;
    hbrt->bucket_array = head_pointer_list;
    return hbrt;
}

/**
 * 获取 hash based routing table 之中的 source_id 和 destination_id
 * @param hbrt
 * @param source_id
 * @param destination_id
 * @return
 */
struct hlist_head *get_bucket_in_hbrt(struct HashBasedRoutingTable *hbrt,
                                      int source_id,
                                      int destination_id) {
    u32 hash_value;
    u32 index_of_bucket;
    int source_dest_pair[2] = {source_id, destination_id};
    hash_value = jhash(source_dest_pair, sizeof(int) * 2, 1234);
    index_of_bucket = hash_value % hbrt->bucket_count;
    return &hbrt->bucket_array[index_of_bucket];
}


/**
 * 判断两个路由表项是否相等
 * @param entry
 * @param source_id
 * @param destination_id
 * @return
 */
int routing_entry_equal_judgement(struct SourceRoutingTableEntry *entry, int source_id, int destination_id) {
    if (entry == NULL) {
        return 1;
    }
    // 只要两个路由表项的 source 和 destination 相同即可
    if ((entry->source_id == source_id) && (entry->destination_id == destination_id)) {
        return 0;
    } else {
        return 1;
    }
}

/**
 * 将路由表项添加到 hbrt 之中
 * @param head_pointer_list
 * @param routing_table_entry
 * @return
 */
int add_entry_to_hbrt(struct HashBasedRoutingTable *hbrt, struct SourceRoutingTableEntry *routing_table_entry) {
    struct hlist_head *hash_bucket = NULL;
    struct SourceRoutingTableEntry *current_entry = NULL;
    struct hlist_node *next = NULL;
    // 首先找到对应的应该存放的 bucket
    hash_bucket = get_bucket_in_hbrt(hbrt,
                                     routing_table_entry->source_id,
                                     routing_table_entry->destination_id);
    if (NULL == hash_bucket) {
        LOG_WITH_PREFIX("cannot find hash bucket");
        kfree(routing_table_entry);
        return -1;  // 找不到 hash_bucket
    }
    hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
        if (0 == routing_entry_equal_judgement(current_entry,
                                               routing_table_entry->source_id,
                                               routing_table_entry->destination_id)) {
            LOG_WITH_PREFIX("already exists route entry");
            free_source_routing_table_entry(routing_table_entry);
            return -2;  // 已经存在
        }
    }
    // 这个时候说明我们真的需要创建一个自己的 node
    INIT_HLIST_NODE(&routing_table_entry->pointer);
    hlist_add_head(&routing_table_entry->pointer, hash_bucket);
    return 0;
}

/**
 * 释放基于哈希的路由表
 * @param hbrt
 * @return
 */
int free_hash_based_routing_table(struct HashBasedRoutingTable* hbrt){
    int index;
    struct hlist_head *hash_bucket = NULL;
    struct SourceRoutingTableEntry *current_entry = NULL;
    struct hlist_node *next;
    for (index = 0; index < hbrt->bucket_count; index++) {
        hash_bucket = &hbrt->bucket_array[index];
        // 每一个 hash_bucket 都被初始化过了，所以不能为NULL
        if (NULL == hash_bucket) {
            LOG_WITH_PREFIX("hash bucket is null");
            return -1;
        }
        hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
            hlist_del(&current_entry->pointer);
            free_source_routing_table_entry(current_entry);
        }
    }
    // 清空 head_pointer_list 引入的 memory 开销
    kfree(hbrt->bucket_array);
    hbrt->bucket_array = NULL;
    // 释放 hbrt
    kfree(hbrt);
    hbrt = NULL;
    LOG_WITH_PREFIX("delete hash based routing table successfully!");
    return 0;
}