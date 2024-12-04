//#include <net/inet_common.h>
#include "tools/tools.h"
#include "hooks/inet_sendmsg/inet_sendmsg.h"
#include "api/test.h"
#include "hooks/transport_layer/udp/udp_sendmsg/udp_sendmsg.h"

char* tcp_sendmsg_str = "tcp_sendmsg";
extern asmlinkage int (*orig_udp_sendmsg)(struct sock *sk, struct msghdr *msg, size_t len);
asmlinkage int (*orig_tcp_sendmsg)(struct sock *sk, struct msghdr *msg, size_t size);

bool resolve_inet_sendmsg_inner_functions_address(void) {
    LOG_WITH_EDGE("start to resolve tcp_sendmsg inner functions address");
    // 结果
    bool resolve_result;
    // 所有的待初始化的函数指针构成的数组
    void* functions[1];
    // 所有的函数名
    char* function_names[1] = {
            tcp_sendmsg_str
    };
    // 解析函数地址
    resolve_result = resolve_functions_addresses(functions, function_names, 1);
    // 将函数地址提取
    orig_tcp_sendmsg = functions[0];
    LOG_WITH_EDGE("end to resolve tcp_sendmsg inner functions address");
    return resolve_result;
}

int self_defined_inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size){
    struct sock *sk = sock->sk;

//    if (unlikely(inet_send_prepare(sk)))
//        return -EAGAIN;

    if (sk->sk_prot->sendmsg == orig_udp_sendmsg){
        int network_type = resolve_network_type_from_sk(sk);
        if (IP_NETWORK_TYPE == network_type) {
            return orig_udp_sendmsg(sk, msg, size);
        } else if (LIR_NETWORK_TYPE == network_type){
            return self_defined_udp_sendmsg(sk, msg,size);;
        } else {
            return -EINVAL;
        }
    } else {
        return INDIRECT_CALL_2(sk->sk_prot->sendmsg, orig_tcp_sendmsg, orig_udp_sendmsg,
                               sk, msg, size);
    }
}