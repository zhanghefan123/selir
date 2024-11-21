#include "structure/source_routing_table_entry.h"

/**
 * 进行源路由表项的创建, 分配内存
 * @param bitset_length bitarray 的长度 (unsigned long 为单位)
 * @return
 */
struct SourceRoutingTableEntry* init_source_routing_table_entry(int bitset_length){
    // 为 source_routing_table_entry 分配内存
    struct SourceRoutingTableEntry* source_routing_table_entry = (struct SourceRoutingTableEntry*)kmalloc(sizeof(struct SourceRoutingTableEntry), GFP_KERNEL);
    // 为 bitset 分配内存
    source_routing_table_entry->bitset = (unsigned long*)kmalloc(sizeof(unsigned long) * bitset_length, GFP_KERNEL);
    // 返回结果
    return source_routing_table_entry;
}

/**
 * 进行源路由表项的创建
 * @param source_routing_table_entry
 */
void free_source_routing_table_entry(struct SourceRoutingTableEntry* source_routing_table_entry){
    if (NULL != source_routing_table_entry) {
        if (NULL != source_routing_table_entry->node_ids) {
            kfree(source_routing_table_entry->node_ids);
        }
        if(NULL != source_routing_table_entry->bitset) {
            kfree(source_routing_table_entry->bitset);
        }
        if (NULL != source_routing_table_entry->link_identifiers){
            kfree(source_routing_table_entry->link_identifiers);
        }
    }
}