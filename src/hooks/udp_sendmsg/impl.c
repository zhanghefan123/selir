#include "hooks/udp_sendmsg/udp_sendmsg.h"
#include "api/test.h"
#include "api/option_resolver.h"
#include "structure/destination_info.h"
#include "structure/source_routing_table.h"
#include "structure/namespace.h"
#include "structure/path_validation_structure.h"

/**
 * 自定义的 udp_sendmsg
 * @param sk
 * @param msg
 * @param len
 * @return
 */
int self_defined_udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len){
    // 通过套接字提取 IPv4 套接字信息
    struct inet_sock *inet = inet_sk(sk);
    // 通过套接字获取 UDP 套接字信息
    struct udp_sock *udp_sock = udp_sk(sk);
    // 相当于 struct sockaddr_in* usin 并且将 msg->msg_name 赋值其中
    DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
    // 源端口
    __be16 sport = inet->inet_sport;
    // 目的端口
    __be16 dport = usin->sin_port;
    int (*getfrag)(void *, char *, int, int, int, struct sk_buff *) = ip_generic_getfrag;
    // 各类长度
    int udp_len = sizeof(struct udphdr);
    int app_len = (int)(len);
    int udp_and_app_len = udp_len + app_len;
    // 命名空间
    struct net* current_ns = sock_net(sk);
    // 路径验证结构
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    // ipcm_cookie 是 IP 传输相关的上下文结构, 让高层协议将一些控制信息传递给 ip_append_data
    struct ipcm_cookie ipc;
    ipcm_init_sk(&ipc, inet);
    ipc.gso_size = READ_ONCE(udp_sock->gso_size);
    // 获取目的地的信息
    struct DestinationInfo* destination_info = resolve_option_for_destination_info(inet->inet_opt);
    // 根据目的地信息查到路由条目
    struct SourceRoutingTableEntry* routing_table_entry = &(pvs->abrt->routes[destination_info->destinations[0]]);
    // 构建 skb
    struct sk_buff* packet;
    return 0;
}