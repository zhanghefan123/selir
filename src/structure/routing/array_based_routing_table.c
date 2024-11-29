#include "tools/tools.h"
#include "structure/routing/array_based_routing_table.h"


/**
 * 进行基于数组的路由表的创建
 * @param number_of_routes 路由的条数
 * @return 返回创建好的路由表
 */
struct ArrayBasedRoutingTable *init_abrt(int number_of_routes) {
    // 分配内存
    struct ArrayBasedRoutingTable *abrt = (struct ArrayBasedRoutingTable *) kmalloc(sizeof(struct ArrayBasedRoutingTable), GFP_KERNEL);
    // 设置路由条数
    abrt->number_of_routes = number_of_routes;
    // 为路由表分配内存
    abrt->routes = (struct RoutingTableEntry **) kmalloc(sizeof(struct RoutingTableEntry*) * number_of_routes,GFP_KERNEL);
    // 进行创建结果的返回
    return abrt;
}

/**
 * 进行基于数组的路由表的释放
 * @param abrt
 */
void free_abrt(struct ArrayBasedRoutingTable *abrt) {
    // 判断 abrt 是否为 NULL, 如果 NULL == abrt, 则返回
    if (NULL != abrt) {
        // 索引
        int index;
        // 判断 routes 是否为 NULL, 如果 NULL == routes 则返回
        if (NULL != abrt->routes) {
            // 遍历所有的路由进行释放
            for (index = 0; index < abrt->number_of_routes; index++) {
                free_routing_table_entry(abrt->routes[index]);
            }
            kfree(abrt->routes);
            abrt->routes = NULL;
        }
        kfree(abrt);
        abrt = NULL;
        LOG_WITH_PREFIX("delete array based routing table successfully!");
    } else {
        LOG_WITH_PREFIX("array based routing table is NULL");
    }
}

/**
 * 根据目的节点 id 在基于数组的路由表之中查找路由表条目
 * @param abrt 基于数组的路由表
 * @param destination 目的节点
 * @return
 */
struct RoutingTableEntry *find_sre_in_abrt(struct ArrayBasedRoutingTable *abrt, int destination) {
    return abrt->routes[destination];
}


/**
 * 将 entry 添加到 abrt 之中
 * @param abrt 基于数组的路由表
 * @param rte 路由表项
 */
void add_entry_to_abrt(struct ArrayBasedRoutingTable* abrt, struct RoutingTableEntry* rte) {
    abrt->routes[rte->destination_id] = rte;
}

/**
 * 根据目的信息, 创建路由计算结果
 * @param abrt 基于数组的路由表
 * @param destination_info 目的节点信息
 * @param bf_effective_bytes 布隆过滤器有效字节数
 * @param number_of_output_interfaces 出接口的数量
 * @return
 */
struct RoutingCalcRes *construct_rcr_with_dest_info_under_abrt(struct ArrayBasedRoutingTable *abrt,
                                                               struct DestinationInfo *destination_info,
                                                               int bf_effective_bytes,
                                                               int number_of_output_interfaces) {
    // 创建 rcr
    struct RoutingCalcRes *rcr = init_rcr(destination_info,
                                          bf_effective_bytes,
                                          number_of_output_interfaces);
    // 索引
    int index;
    // 遍历所有的目的节点 id
    for (index = 0; index < destination_info->number_of_destinations; index++) {
        // 通过 id 进行路由表的查找
        struct RoutingTableEntry *sre = find_sre_in_abrt(abrt, destination_info->destinations[index]);
        // 相应的出接口
        struct InterfaceTableEntry *ite = sre->output_interface;
        // 设置相应的出接口
        if (NULL == rcr->output_interfaces[ite->index]) {
            rcr->output_interfaces[ite->index] = ite->interface;
        }
        // 进行布隆过滤器底层的数组的更新
        unsigned char *bloom_filter_bit_set = rcr->bitsets + (ite->index * bf_effective_bytes);
        memory_or(bloom_filter_bit_set, sre->bitset, bf_effective_bytes);
    }
    return rcr;
}