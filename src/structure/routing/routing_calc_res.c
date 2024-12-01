#include "structure/routing/routing_calc_res.h"

/**
 * 进行路由计算返回结果的创建
 * @param destination_info 目的信息
 * @param bf_effective_bytes 布隆过滤器的有效字节数量
 * @param number_of_output_interfaces 出接口数量
 * @return
 */
struct RoutingCalcRes *init_rcr(int source, struct DestinationInfo* destination_info, struct PathValidationStructure* pvs) {
    // 创建路由计算结果
    struct RoutingCalcRes *route_calculation_result = (struct RoutingCalcRes *) (kmalloc(
            sizeof(struct RoutingCalcRes), GFP_KERNEL));
    route_calculation_result->bitset = (unsigned char *) (kmalloc(pvs->bloom_filter->effective_bytes, GFP_KERNEL));
    route_calculation_result->output_interface = NULL;
    route_calculation_result->source = source;
    route_calculation_result->destination_info = destination_info;
    return route_calculation_result;
}

/**
 * 进行 route_calculation_result 的释放
 * @param route_calculation_result
 */
void free_rcr(struct RoutingCalcRes *route_calculation_result) {
    if (NULL != route_calculation_result){
        // 进行 bitsets 的释放
        if (NULL != route_calculation_result->bitset) {
            kfree(route_calculation_result->bitset);
        }
        // 进行 RoutingCalcRes 结构占用的内存的释放
        kfree(route_calculation_result);
    }
}