#include "tools/tools.h"
#include "structure/routing/variables.h"
#include "structure/routing/hash_based_routing_table.h"

/**
 * 进行基于哈希的路由表的初始化
 * @param bucket_count
 * @return
 */
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
        INIT_HLIST_HEAD(&head_pointer_list[index]);
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
int routing_entry_equal_judgement(struct RoutingTableEntry *entry, int source_id, int destination_id) {
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
int add_entry_to_hbrt(struct HashBasedRoutingTable *hbrt, struct RoutingTableEntry *routing_table_entry) {
    struct hlist_head *hash_bucket = NULL;
    struct RoutingTableEntry *current_entry = NULL;
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
            free_routing_table_entry(routing_table_entry);
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
int free_hbrt(struct HashBasedRoutingTable *hbrt) {
    // 这里首先判断要进行 free 的 hbrt 是否为 NULL
    if(NULL != hbrt){
        int index;
        struct hlist_head *hash_bucket = NULL;
        struct RoutingTableEntry *current_entry = NULL;
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
                free_routing_table_entry(current_entry);
            }
        }
        // 清空 head_pointer_list 引入的 memory 开销
        kfree(hbrt->bucket_array);
        hbrt->bucket_array = NULL;
        // 释放 hbrt
        kfree(hbrt);
        hbrt = NULL;
        LOG_WITH_PREFIX("delete hash based routing table successfully!");
    } else {
        LOG_WITH_PREFIX("hash based routing table is NULL");
    }
    return 0;
}

/**
 * 根据源和目的地找到对应的路由表条目
 * @param hbrt 基于哈希的路由表结构
 * @param source 源
 * @param destination 目的
 * @return 找到的路由表项
 */
struct RoutingTableEntry *find_sre_in_hbrt(struct HashBasedRoutingTable *hbrt, int source, int destination) {
    struct hlist_head *hash_bucket = NULL;
    struct RoutingTableEntry *current_entry;
    struct hlist_node *next;
    hash_bucket = get_bucket_in_hbrt(hbrt, source, destination);
    if (NULL == hash_bucket) {
        LOG_WITH_PREFIX("cannot find entry because cannot find hash bucket");
        return NULL;
    }
    hlist_for_each_entry_safe(current_entry, next, hash_bucket, pointer) {
        if (0 == routing_entry_equal_judgement(current_entry, source, destination)) {
            return current_entry;
        }
    }
    return NULL;
}

/**
 *
 * @param hbrt 基于哈希的路由表
 * @param destination_info 目的节点信息
 * @param bf_effective_bytes bf 的有效字节数
 * @param source_node_id 源节点 id
 * @param number_of_interfaces 接口的数量
 * @return
 */
struct RoutingCalcRes *construct_rcr_with_dest_info_under_hbrt(struct HashBasedRoutingTable *hbrt,
                                                               struct DestinationInfo *destination_info,
                                                               int bf_effective_bytes,
                                                               int source_node_id) {
    // 1.索引
    int index;

    // 2.创建 rcr
    struct RoutingCalcRes *rcr = init_rcr(bf_effective_bytes);

    // 3.使用基于主节点的方式
    // -----------------------------------------------------------------------------------------
    // 3.1  首先找到主节点
    int primaryNodeId = destination_info->destinations[0];
    // 3.2  找到到主节点的路由
    struct RoutingTableEntry *source_to_primary = find_sre_in_hbrt(hbrt,
                                                                   source_node_id,
                                                                   primaryNodeId);

    // 2. 更新出接口和 bitset
    rcr->output_interface = source_to_primary->output_interface->interface;
    memory_or(rcr->bitset, source_to_primary->bitset, bf_effective_bytes);

    // 3. 接着找到主节点到其他节点的路由
    for (index = 1; index < destination_info->number_of_destinations; index++) {
        int otherNodeId = destination_info->destinations[index];
        struct RoutingTableEntry *primary_to_other = find_sre_in_hbrt(hbrt,
                                                                      primaryNodeId,
                                                                      otherNodeId);
        // 进行 bitset 的更新
        memory_or(rcr->bitset, primary_to_other->bitset, bf_effective_bytes);
    }

    // 4. 进行结果的返回
    return rcr;
}