//
// Created by root on 2/8/24.
//
#include "tools/tools.h"
#include "prepare/resolve_function_address.h"
#include "hooks/ipv6_rcv/ipv6_rcv.h"
#include "hooks/ip6_rcv_finish_core/ip6_rcv_finish_core.h"
#include "hooks/tcp_v4_rcv/tcp_v4_rcv.h"
#include "hooks/tcp_v4_do_rcv/tcp_v4_do_rcv.h"
#include "hooks/tcp_rcv_established/tcp_rcv_established.h"

/*
 * 使用 kallsyms_lookup_name 进行函数地址的查找
 */
bool resolve_function_address(void){
    bool result;
    result = resolve_ipv6_rcv_inner_functions_address();
    if(!result){
        LOG_WITH_PREFIX("resolve ip6_rcv failed");
        return result;
    }
    result = resolve_ip6_rcv_finish_core_inner_functions_address();
    if(!result){
        LOG_WITH_PREFIX("resolve ip6_rcv_finish_core failed");
        return result;
    }
    result = resolve_tcp_v4_rcv_inner_functions_address();
    if(!result){
        LOG_WITH_PREFIX("resolve tcp_v4_rcv failed");
        return result;
    }
    result = resolve_tcp_v4_do_rcv_inner_functions_address();
    if(!result){
        LOG_WITH_PREFIX("resolve tcp_v4_do_rcv failed");
        return result;
    }
    result = resolve_tcp_rcv_established_inner_functions_address();
    if(!result){
        LOG_WITH_PREFIX("resolve tcp_rcv_established failed");
        return result;
    }
    return result;
}