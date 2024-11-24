#include "structure/path_validation_structure.h"
#include "structure/interface_table_entry.h"


/**
 * 初始化网络命名空间之中的 path_validation_structure
 * @param current_ns
 */
struct PathValidationStructure* initialize_path_validation_structure(void) {
    struct PathValidationStructure* path_validation_structure = (struct PathValidationStructure*)kmalloc(sizeof(struct PathValidationStructure), GFP_KERNEL);
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


/**
 * 初始化路径验证数据结构
 * @param number_of_routes 总的路由条数
 * @param number_of_interfaces 总的接口数量
 */
void initialize_routing_and_forwarding_table(struct PathValidationStructure* pvs, int number_of_routes, int number_of_interfaces){
    // 设置路由条数
    pvs->number_of_routes = number_of_routes;
    // 为路由表分配内存
    pvs->source_routing_table = (struct SourceRoutingTableEntry*)kmalloc(sizeof(struct SourceRoutingTableEntry) * number_of_routes, GFP_KERNEL);
    // 设置接口数量
    pvs->number_of_interfaces = number_of_interfaces;
    // 为接口表分配内存
    pvs->interface_table = (struct InterfaceTableEntry*)kmalloc(sizeof(struct InterfaceTableEntry) * number_of_interfaces, GFP_KERNEL);
}


/**
 * 利用链路标识进行接口表的查找
 * @param pvs
 * @param link_identifier
 * @return
 */
struct InterfaceTableEntry* find_interface_entry_with_link_identifier(struct PathValidationStructure* pvs, int link_identifier){
    int index;
    struct InterfaceTableEntry* result = NULL;
    for(index = 0; index < pvs->number_of_interfaces; index++){
        if(pvs->interface_table[index].link_identifier == link_identifier){
            result = &(pvs->interface_table[index]);
            break;
        }
    }
    return result;
}


