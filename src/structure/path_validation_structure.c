#include "structure/path_validation_structure.h"
#include "structure/interface_table.h"


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
    // 进行基于数组路由表的释放
    free_array_based_routing_table(path_validation_structure->abrt);
    // 进行基于数组的接口表的释放
    free_array_based_interface_table(path_validation_structure->abit);
    // 进行布隆过滤器的释放
    delete_bloom_filter(path_validation_structure->bloom_filter);
}


/**
 * 初始化路径验证数据结构
 * @param number_of_routes 总的路由条数
 * @param number_of_interfaces 总的接口数量
 */
void initialize_routing_and_forwarding_table(struct PathValidationStructure* pvs, int routing_table_type, int number_of_routes, int number_of_interfaces){
    if(ARRAY_BASED_ROUTING_TABLE_TYPE == routing_table_type) {
        pvs->abrt = initialize_array_based_routing_table(number_of_routes);
        pvs->routing_table_type = ARRAY_BASED_ROUTING_TABLE_TYPE;
    } else {
        pvs->routing_table_type = HASH_BASED_ROUTING_TABLE_TYPE;
    }
    pvs->abit = initialize_array_based_interface_table(number_of_interfaces);
}
