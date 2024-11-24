#include "structure/source_routing_table.h"

/**
 * 进行源路由表项的创建, 分配内存
 * @param bitset_length bitarray 的长度 (unsigned long 为单位)
 * @return
 */
struct SourceRoutingTableEntry* init_source_routing_table_entry(int effective_bytes){
    // 为 source_routing_table_entry 分配内存
    struct SourceRoutingTableEntry* source_routing_table_entry = (struct SourceRoutingTableEntry*)kmalloc(sizeof(struct SourceRoutingTableEntry), GFP_KERNEL);
    // 为 bitset 分配内存
    source_routing_table_entry->bitset = (unsigned char*)kmalloc(sizeof(unsigned char) * effective_bytes, GFP_KERNEL);
    // 设置有效字节数
    source_routing_table_entry->effective_bytes = effective_bytes;
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

/**
 * 进行基于数组的路由表的创建
 * @param number_of_routes 路由的条数
 * @return
 */
struct ArrayBasedRoutingTable* initialize_array_based_routing_table(int number_of_routes){
    // 分配内存
    struct ArrayBasedRoutingTable* abrt = (struct ArrayBasedRoutingTable*)kmalloc(sizeof(struct ArrayBasedRoutingTable), GFP_KERNEL);
    // 设置路由条数
    abrt->number_of_routes = number_of_routes;
    // 为路由表分配内存
    abrt->routes = (struct SourceRoutingTableEntry*) kmalloc(sizeof(struct SourceRoutingTableEntry) * number_of_routes, GFP_KERNEL);
    // 进行创建结果的返回
    return abrt;
}

/**
 * 进行基于数组的路由表的释放
 * @param abrt
 */
void free_array_based_routing_table(struct ArrayBasedRoutingTable* abrt){
    int index;
    if(NULL != abrt){
        if(NULL != abrt->routes){
            for(index = 0; index < abrt->number_of_routes; index++){
                free_source_routing_table_entry(&(abrt->routes[index]));
            }
            kfree(abrt->routes);
        }
        kfree(abrt);
        abrt = NULL;
    }

}