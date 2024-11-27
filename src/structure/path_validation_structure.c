#include "structure/path_validation_structure.h"
#include "structure/interface/interface_table.h"
#include "structure/routing/variables.h"
#include "structure/routing/array_based_routing_table.h"
#include "structure/routing/hash_based_routing_table.h"
#include "tools/tools.h"


/**
 * 初始化网络命名空间之中的 path_validation_structure
 * @param current_ns
 */
struct PathValidationStructure *initialize_pvs(void) {
    struct PathValidationStructure *path_validation_structure = (struct PathValidationStructure *) kmalloc(
            sizeof(struct PathValidationStructure), GFP_KERNEL);
    return path_validation_structure;
}


/**
 * 进行 path_validation_structure 空间的释放
 * @param path_validation_structure 路径验证数据结构
 */
void free_pvs(struct PathValidationStructure *pvs) {
    if (pvs->routing_table_type == ARRAY_BASED_ROUTING_TABLE_TYPE) {
        // 进行基于数组路由表的释放
        free_abrt(pvs->abrt);
    } else if (pvs->routing_table_type == HASH_BASED_ROUTING_TABLE_TYPE) {
        // 进行基于哈希的路由表的释放
        free_hbrt(pvs->hbrt);
    } else {
        LOG_WITH_PREFIX("unknown routing table");
    }
    // 进行基于数组的接口表的释放
    free_array_based_interface_table(pvs->abit);
    // 进行布隆过滤器的释放
    delete_bloom_filter(pvs->bloom_filter);
}


/**
 * 初始化路径验证数据结构
 * @param number_of_routes 总的路由条数
 * @param number_of_interfaces 总的接口数量
 */
void initialize_routing_and_forwarding_table(struct PathValidationStructure *pvs,
                                             int routing_table_type,
                                             int routing_type,
                                             int number_of_routes_or_buckets,
                                             int number_of_interfaces) {
    if (ARRAY_BASED_ROUTING_TABLE_TYPE == routing_table_type) {
        pvs->abrt = init_abrt(number_of_routes_or_buckets);
        pvs->routing_table_type = ARRAY_BASED_ROUTING_TABLE_TYPE;
    } else {
        pvs->hbrt = initialize_hbrt(number_of_routes_or_buckets);
        pvs->routing_table_type = HASH_BASED_ROUTING_TABLE_TYPE;
    }
    pvs->routing_type = routing_type;
    pvs->abit = initialize_array_based_interface_table(number_of_interfaces);
}
