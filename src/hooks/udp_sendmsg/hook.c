#include "api/test.h"
#include "hooks/udp_sendmsg/udp_sendmsg.h"


// 原来的函数地址
asmlinkage int (*orig_udp_sendmsg)(struct sock *sk, struct msghdr *msg, size_t len); // 原来的 udp_sendmsg

/**
 * callback function
 * @param sk
 * @param msg
 * @param len
 * @return
 */
asmlinkage int hook_udp_sendmsg(struct sock* sk, struct msghdr* msg, size_t len){
    if(test_if_lir_socket(sk)){
        return self_defined_udp_sendmsg(sk, msg, len);
    } else {
        return orig_udp_sendmsg(sk, msg, len);
    }
}

/**
 * 进行 hook
 */
void add_udp_sendmsg_to_hook(void) {
    hooks[number_of_hook].name = "tcp_v4_rcv";
    hooks[number_of_hook].function = hook_udp_sendmsg,
    hooks[number_of_hook].original = &orig_udp_sendmsg;
    number_of_hook += 1;
}