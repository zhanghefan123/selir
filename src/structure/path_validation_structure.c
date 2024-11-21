#include "structure/path_validation_structure.h"
#include "structure/interface_table_entry.h"

/**
 * 初始化路径验证数据结构
 * @param number_of_routes 总的路由条数
 * @param number_of_interfaces 总的接口数量
 */
struct PathValidationStructure* initialize_path_validation_structure(int number_of_routes, int number_of_interfaces){
    // 为 PathValidationStructure 进行内存分配
    struct PathValidationStructure* path_validation_structure = (struct PathValidationStructure*)kmalloc(sizeof(struct PathValidationStructure), GFP_KERNEL);
    // 设置路由条数
    path_validation_structure->number_of_routes = number_of_routes;
    // 为路由表分配内存
    path_validation_structure->source_routing_table = (struct SourceRoutingTableEntry*)kmalloc(sizeof(struct SourceRoutingTableEntry) * number_of_routes, GFP_KERNEL);
    // 设置接口数量
    path_validation_structure->number_of_interfaces = number_of_interfaces;
    // 为接口表分配内存
    path_validation_structure->interface_table = (struct InterfaceTableEntry*)kmalloc(sizeof(struct InterfaceTableEntry) * number_of_interfaces, GFP_KERNEL);
    // 返回初始化好的结构
    return path_validation_structure;
}

/**
 * 进行 path_validation_structure 空间的释放
 * @param path_validation_structure 路径验证数据结构
 */
void free_path_validation_structure(struct PathValidationStructure* path_validation_structure){
    int index;
    // 进行路由表内存的释放
    for(index = 0; index < path_validation_structure->number_of_routes; index++){
        free_source_routing_table_entry(&(path_validation_structure->source_routing_table[index]));
    }
    kfree(path_validation_structure->source_routing_table);
    path_validation_structure->source_routing_table = NULL;
    // 进行接口表内存的释放
    kfree(path_validation_structure->interface_table);
    path_validation_structure->interface_table = NULL;
    // 进行布隆过滤器的释放
    delete_bloom_filter(path_validation_structure->bloom_filter);
}