#include "structure/routing/routing_calc_res.h"

/**
 * 进行路由计算返回结果的创建
 * @param destination_info 目的信息
 * @param bf_effective_bytes 布隆过滤器的有效字节数量
 * @param number_of_output_interfaces 出接口数量
 * @return
 */
struct RoutingCalcRes *init_rcr(struct DestinationInfo *destination_info,
                                int bf_effective_bytes,
                                int number_of_output_interfaces) {
    // 索引
    int index;
    // 创建路由计算结果
    struct RoutingCalcRes *route_calculation_result = (struct RoutingCalcRes *) (kmalloc(
            sizeof(struct RoutingCalcRes), GFP_KERNEL));
    // 单个 bf 的 byte 的个数
    int single_bf_size = bf_effective_bytes;
    // 总的 bitsets 大小
    int bitsets_size = (int) (sizeof(unsigned char) * single_bf_size * number_of_output_interfaces);
    // 为 bitsets 分配内存
    route_calculation_result->bitsets = (unsigned char *) (kmalloc(bitsets_size, GFP_KERNEL));
    memset(route_calculation_result->bitsets, 0, bitsets_size);
    // 为所有出接口指针分配内存
    route_calculation_result->output_interfaces = (struct net_device **) (kmalloc(
            sizeof(struct net_device *) * number_of_output_interfaces, GFP_KERNEL));
    // 遍历, 初始化为 NULL
    for (index = 0; index < number_of_output_interfaces; index++) {
        route_calculation_result->output_interfaces[index] = NULL;
    }
    // 存储目的信息
    route_calculation_result->destination_info = destination_info;
    // 进行结果的返回
    return route_calculation_result;
}

/**
 * 进行 route_calculation_result 的释放
 * @param route_calculation_result
 */
void free_rcr(struct RoutingCalcRes *route_calculation_result) {
    // 进行 bitsets 的释放
    if (NULL != route_calculation_result->bitsets) {
        kfree(route_calculation_result->bitsets);
    }
    // 进行不同出接口所占用内存的释放
    if (NULL != route_calculation_result->output_interfaces) {
        kfree(route_calculation_result->output_interfaces);
    }
}