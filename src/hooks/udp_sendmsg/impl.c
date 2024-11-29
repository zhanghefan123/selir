#include <net/udp.h>
#include <net/udplite.h>
#include <linux/bpf-cgroup.h>

#include "api/test.h"
#include "tools/tools.h"
#include "structure/routing/variables.h"
#include "structure/namespace/namespace.h"
#include "hooks/udp_sendmsg/udp_sendmsg.h"
#include "hooks/udp_send_skb/udp_send_skb.h"
#include "hooks/ip_make_skb/ip_make_skb.h"
#include "hooks/ip_append_data/ip_append_data.h"
#include "api/option_resolver.h"



char *ip_cmsg_send_str = "ip_cmsg_send";

asmlinkage int (*orig_ip_cmsg_send)(struct sock *sk, struct msghdr *msg, struct ipcm_cookie *ipc, bool allow_ipv6);


/**
 * 解析 udp_sendmsg 内部的函数
 * @return
 */
bool resolve_udp_sendmsg_inner_functions(void) {
    LOG_WITH_EDGE("start to resolve udp_sendmsg inner functions address");
    // 解析结果
    bool resolve_result;
    // 所有的待初始化的函数的函数指针过程的数组
    void *functions[1];
    char *function_names[1] = {
            ip_cmsg_send_str,
    };
    resolve_result = resolve_functions_addresses(functions, function_names, 1);
    orig_ip_cmsg_send = functions[0];
    LOG_WITH_EDGE("end to resolve udp_sendmsg inner functions address");
    return resolve_result;
}

/**
 * 自定义的 udp_sendmsg
 * @param sk
 * @param msg
 * @param len
 * @return
 */
int self_defined_udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len) {
    struct inet_sock *inet = inet_sk(sk);
    struct udp_sock *up = udp_sk(sk);
    DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
    struct flowi4 fl4_stack;
    struct flowi4 *fl4;
    int ulen = len;
    struct ipcm_cookie ipc;
    struct rtable *rt = NULL;
    int free = 0;
    int connected = 0;
    __be32 daddr, faddr, saddr;
    __be16 dport;
    u8 tos;
    int err, is_udplite = IS_UDPLITE(sk);
    int corkreq = READ_ONCE(up->corkflag) || msg->msg_flags & MSG_MORE;
    int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
    struct sk_buff *skb;
    struct ip_options_data opt_copy;
    // zhf add variables
    // -----------------------------------------------------
    // 1. 路由计算结果
    struct RoutingCalcRes* rcr;
    // 2. 网络命名空间
    struct net* current_ns;
    // 3. 路径验证数据结构
    struct PathValidationStructure* pvs;
    // 4. 选项
    struct ip_options_rcu* option;
    // 5. 由选项解析的目的地
    struct DestinationInfo* destination_info;
    // 6. 变量赋值
    current_ns = sock_net(sk);
    pvs = get_pvs_from_ns(current_ns);
    option = inet->inet_opt;
    destination_info = resolve_option_for_destination_info(option);
    // -----------------------------------------------------

    // zhf add new code -- search route
    // -----------------------------------------------------
    if (pvs->routing_table_type == ARRAY_BASED_ROUTING_TABLE_TYPE) {
        rcr = construct_rcr_with_dest_info_under_abrt(pvs->abrt,
                                                      destination_info,
                                                      (int)(pvs->bloom_filter->effective_bytes));
    } else if (pvs->routing_table_type == HASH_BASED_ROUTING_TABLE_TYPE) {
        rcr = construct_rcr_with_dest_info_under_hbrt(pvs->hbrt,
                                                      destination_info,
                                                      (int)(pvs->bloom_filter->effective_bytes),
                                                      pvs->node_id);
    } else {
        LOG_WITH_PREFIX("unsupported routing table type");
        return -EOPNOTSUPP;
    }
    free_rcr(rcr);
    free_destination_info(destination_info);
    // -----------------------------------------------------

    // 当长度超大, 返回消息大小错误信息
    if (len > 0xFFFF)
        return -EMSGSIZE;

    /*
     *	Check the flags.
     */

    // 不支持 MSG_OOB
    if (msg->msg_flags & MSG_OOB) /* Mirror BSD error message compatibility */
        return -EOPNOTSUPP;

    // frag 方式
    getfrag = is_udplite ? udplite_getfrag : ip_generic_getfrag;

    fl4 = &inet->cork.fl.u.ip4;

    // 在以超快的速度发送的时候这里面的代码均没有被调用 (uncalled)
    // -----------------------------------------------------
    if (up->pending) {
        lock_sock(sk);
        if (likely(up->pending)) {
            if (unlikely(up->pending != AF_INET)) {
                release_sock(sk);
                return -EINVAL;
            }
            goto do_append_data;
        }
        release_sock(sk);
    }
    // -----------------------------------------------------
    ulen += sizeof(struct udphdr); // ulen 应该是用户数据大小, ulen + udp 首部 = 应用层 + 传输层大小

    // 验证地址
    // -----------------------------------------------------
    // usin 是一个 sockaddr_in --> 代表的是目的地址
    // usin->sin_addr --> 代表的是目的 ip
    // usin->sin_port --> 代表的是目的 port
    if (usin) {
        // 首先判断地址是否长度没错
        if (msg->msg_namelen < sizeof(*usin))
            return -EINVAL;
        // 接着判断协议簇是否没错
        if (usin->sin_family != AF_INET) {
            if (usin->sin_family != AF_UNSPEC)
                return -EAFNOSUPPORT;
        }
        // 初始化目的地址和目的端口
        // ---------------------------
        daddr = usin->sin_addr.s_addr;
        dport = usin->sin_port;
        // ---------------------------

        // 如果目的端口为0, 则返回错误
        if (dport == 0)
            return -EINVAL;
    } else {
        // 当 usin 为 NULL 时，说明没有提供明确的目标地址信息（msg->msg_name 不包含目标地址），此时系统会使用已经存在的连接信息来决定目标地址和端口
        // 比如当 udp 处于连接状态的时候
        if (sk->sk_state != TCP_ESTABLISHED)
            return -EDESTADDRREQ;
        daddr = inet->inet_daddr;
        dport = inet->inet_dport;
        /* Open fast path for connected socket.
           Route will not be used, if at least one option is set.
         */
        connected = 1;
    }
    // -----------------------------------------------------

    // ipcm_init_sk 函数会使用 inet 套接字相关的信息来填充 ipc 结构体。这些信息用于 IP 层数据包的处理，比如源 IP 地址、目的 IP 地址、TTL、优先级等。
    // -----------------------------------------------------
    ipcm_init_sk(&ipc, inet);
    ipc.gso_size = READ_ONCE(up->gso_size);
    // -----------------------------------------------------

    // 在以超快的速度发送的时候这里面的代码均没有被调用 (uncalled)
    // 这是 struct msghdr 结构体中的一个字段，它表示消息中附加的控制数据（CMSG）的长度.
    // 如果该值非零，表示有附加的控制消息存在。控制消息通常用于传递一些与数据包发送相关的附加参数（如 GSO、大数据包分片、路由选项等）.
    // -----------------------------------------------------
    if (msg->msg_controllen) {
        err = udp_cmsg_send(sk, msg, &ipc.gso_size);
        if (err > 0)
            err = orig_ip_cmsg_send(sk, msg, &ipc, sk->sk_family == AF_INET6);
        if (unlikely(err < 0)) {
            kfree(ipc.opt);
            return err;
        }
        if (ipc.opt)
            free = 1;
        connected = 0;
    }
    // -----------------------------------------------------

    // (original code) 进行选项的处理, 不管在有没有 socket 配置选项的情况下, 都会进入
    // -----------------------------------------------------
    /*
    if (!ipc.opt) {
        // lir 不用执行这一段逻辑, 原 ip 执行这一段逻辑
        struct ip_options_rcu *inet_opt;
        rcu_read_lock();
        inet_opt = rcu_dereference(inet->inet_opt);
        if (inet_opt) {
            memcpy(&opt_copy, inet_opt,
                   sizeof(*inet_opt) + inet_opt->opt.optlen);
            ipc.opt = &opt_copy.opt;
        }
        rcu_read_unlock();
    }
     */
    // -----------------------------------------------------

    // 这段代码主要处理的是通过 BPF（Berkeley Packet Filter）程序对 UDP 数据包进行过滤和处理
    // -----------------------------------------------------
    // 1. cgroup_bpf_enabled(CGROUP_UDP4_SENDMSG)：检查是否启用了 cgroup BPF 程序,
    // 用于过滤和处理 UDP 数据包的发送操作。CGROUP_UDP4_SENDMSG 是一个用于标识 UDPv4 发送消息的 cgroup 类型。
    // !connected：确保当前的套接字不是处于已连接状态。这个条件的目的是确保只对非连接套接字进行 BPF 程序处理。
    if (cgroup_bpf_enabled(CGROUP_UDP4_SENDMSG) && !connected) {

        // 2. 这一行调用了 BPF 程序，运行一个与 UDP 发送消息相关的 BPF 程序 BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK。
        // BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK 是用于调用 BPF 程序并对 UDP 发送数据包进行处理。
        err = BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK(sk,(struct sockaddr *) usin, &ipc.addr);
        if (err)
            // 如果上面的 BPF 程序执行返回了错误（err 不为零），则直接跳转到 out_free 标签，进行错误处理，可能是释放资源等操作。
            goto out_free;

        // 3. 由于 bpf 程序可能修改地址, 这里重新进行地址验证
        if (usin) {
            if (usin->sin_port == 0) {
                /* BPF program set invalid port. Reject it. */
                err = -EINVAL;
                goto out_free;
            }
            daddr = usin->sin_addr.s_addr;
            dport = usin->sin_port;
        }
    }
    // -----------------------------------------------------

    // saddr 指的是源地址, 在我们发送数据的时候他还没有被初始化, 依然为 0.0.0.0
    saddr = ipc.addr;
    // faddr 代表的是 final destination address
    // 在一些协议中，faddr 可能表示经过某些操作或选项（比如源路由）处理后的最终目标地址. 如果没有复杂的处理，faddr 和 daddr 是相同的。
    ipc.addr = faddr = daddr;
    // printk(KERN_EMERG "ipc.addr = faddr = daddr = %pI4", &ipc.addr); // ipc.addr = faddr = daddr = 192.168.0.10

    // 如果选项为源路由的话
    // -----------------------------------------------------
    if (ipc.opt && ipc.opt->opt.srr) {
        if (!daddr) {
            err = -EINVAL;
            goto out_free;
        }
        faddr = ipc.opt->opt.faddr; // 从源路由选项之中获取最终地址
        connected = 0;
    }
    // -----------------------------------------------------

    // 根据网络协议栈中的选项（如路由、QoS等）来设置Type of Service (ToS) 字段和路由选项
    // -----------------------------------------------------
    tos = get_rttos(&ipc, inet);
    if (sock_flag(sk, SOCK_LOCALROUTE) ||
        (msg->msg_flags & MSG_DONTROUTE) ||
        (ipc.opt && ipc.opt->opt.is_strictroute)) {
        tos |= RTO_ONLINK;
        connected = 0;
    }
    // -----------------------------------------------------


    // -----------------------------------------------------
    if (ipv4_is_multicast(daddr)) { // 判断是否为多播地址 224.0.0.0 到 239.255.255.255
        // ipc.oif 是指发送数据包时使用的输出接口的ifindex
        // 这里判断 ipc.oif 是否为空，或者检查 oif 是否为 L3（网络层）主设备接口。
        if (!ipc.oif || netif_index_is_l3_master(sock_net(sk), ipc.oif))
            ipc.oif = inet->mc_index;
        if (!saddr)
            saddr = inet->mc_addr;
        connected = 0;
    } else if (!ipc.oif) {
        ipc.oif = inet->uc_index; // 如果未设置 oif，则使用 inet->uc_index 作为默认的单播接口索引。
    } else if (ipv4_is_lbcast(daddr) && inet->uc_index) {
        // 这里检查目标地址是否为 IPv4 本地广播地址（即 255.255.255.255）。本地广播地址表示数据包应发送到本地网络上的所有设备。
        /* oif is set, packet is to local broadcast and
         * uc_index is set. oif is most likely set
         * by sk_bound_dev_if. If uc_index != oif check if the
         * oif is an L3 master and uc_index is an L3 slave.
         * If so, we want to allow the send using the uc_index.
         *
         * 如果 oif 已经设置，并且目标地址是本地广播地址，且 uc_index 被设置，那么就需要检查 oif 和 uc_index 是否匹配。
         * 如果 uc_index 不等于 oif，则检查 oif 是否为 L3 主设备，并且 uc_index 是否为 L3 从设备。这样做是为了确保能够通过单播接口进行发送。
         */
        if (ipc.oif != inet->uc_index &&
            ipc.oif == l3mdev_master_ifindex_by_index(sock_net(sk),
                                                      inet->uc_index)) {
            ipc.oif = inet->uc_index;
        }
    }

    // 如果是处于连接的状态 -> 直接从缓存之中拿路由
    if (connected)
        rt = (struct rtable *) sk_dst_check(sk, 0); // 调用 sk_get_dest 拿到 struct dst_entry

    // 基本都会进入到这里进行路由的计算 (called)
    // ----------------------------------------------------------------------------
    if (!rt) {
        LOG_WITH_PREFIX("without route");
        struct net *net = sock_net(sk);
        __u8 flow_flags = inet_sk_flowi_flags(sk);

        fl4 = &fl4_stack;

        // 进行字段的初始化
        /*
        fl4->flowi4_oif = oif; (*)
        fl4->flowi4_iif = LOOPBACK_IFINDEX; (*)
        fl4->flowi4_l3mdev = 0;
        fl4->flowi4_mark = mark;
        fl4->flowi4_tos = tos;
        fl4->flowi4_scope = scope; (*)
        fl4->flowi4_proto = proto; (*)
        fl4->flowi4_flags = flags; (*)
        fl4->flowi4_secid = 0;
        fl4->flowi4_tun_key.tun_id = 0;
        fl4->flowi4_uid = uid;
        fl4->daddr = daddr; (*)
        fl4->saddr = saddr; (*)
        fl4->fl4_dport = dport; (*)
        fl4->fl4_sport = sport; (*)
        fl4->flowi4_multipath_hash = 0;
         */
        flowi4_init_output(fl4, ipc.oif, ipc.sockc.mark, tos,
                           RT_SCOPE_UNIVERSE, sk->sk_protocol,
                           flow_flags,
                           faddr, saddr, dport, inet->inet_sport,
                           sk->sk_uid);

        security_sk_classify_flow(sk, flowi4_to_flowi_common(fl4));
        rt = ip_route_output_flow(net, fl4, sk);
        if (IS_ERR(rt)) {
            err = PTR_ERR(rt);
            rt = NULL;
            if (err == -ENETUNREACH)
                IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
            goto out;
        }

        err = -EACCES;
        if ((rt->rt_flags & RTCF_BROADCAST) &&
            !sock_flag(sk, SOCK_BROADCAST))
            goto out;
        if (connected)
            sk_dst_set(sk, dst_clone(&rt->dst));
    }
    // ----------------------------------------------------------------------------

    // uncalled
    // ----------------------------------------------------------------------------
    if (msg->msg_flags & MSG_CONFIRM) {
        LOG_WITH_PREFIX("go to confirm");
        goto do_confirm;
    }
    // ----------------------------------------------------------------------------
    back_from_confirm:

    saddr = fl4->saddr; // 当路由过程完成了之后才能获取源地址
    //    printk(KERN_EMERG "after routing saddr = %pI4", &saddr); // after routing saddr = 192.168.0.1
    if (!ipc.addr)
        daddr = ipc.addr = fl4->daddr;

    /* Lockless fast path for the non-corking case. */
    // 如果没有进行 cork (called)
    // ----------------------------------------------------------------------------
    if (!corkreq) {
        struct inet_cork cork;
        skb = self_defined_ip_make_skb(sk, fl4, getfrag, msg, ulen,
                                       sizeof(struct udphdr), &ipc, &rt,
                                       &cork, msg->msg_flags);
        err = PTR_ERR(skb);
        if (!IS_ERR_OR_NULL(skb))
            err = self_defined_udp_send_skb(skb, fl4, &cork);
        goto out;
    }
    // ----------------------------------------------------------------------------

    // -------------------------------------------------------- 这里的内容都被跳过了 (因为 goto out) --------------------------------------------------------

    lock_sock(sk);
    if (unlikely(up->pending)) {
        LOG_WITH_PREFIX("up->pending");
        /* The socket is already corked while preparing it. */
        /* ... which is an evident application bug. --ANK */
        release_sock(sk);

        net_dbg_ratelimited("socket already corked\n");
        err = -EINVAL;
        goto out;
    }

    /*
     *	Now cork the socket to pend data.
     */
    fl4 = &inet->cork.fl.u.ip4;
    fl4->daddr = daddr;
    fl4->saddr = saddr;
    fl4->fl4_dport = dport;
    fl4->fl4_sport = inet->inet_sport;
    up->pending = AF_INET;

    do_append_data:
    up->len += ulen;
    err = self_defined_ip_append_data(sk, fl4, getfrag, msg, ulen,
                                      sizeof(struct udphdr), &ipc, &rt,
                                      corkreq ? msg->msg_flags | MSG_MORE : msg->msg_flags);
    if (err)
        udp_flush_pending_frames(sk);
    else if (!corkreq)
        err = udp_push_pending_frames(sk);
    else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
        up->pending = 0;
    release_sock(sk);

    // -------------------------------------------------------- 这里的内容都被跳过了 (因为 goto out)  --------------------------------------------------------

    out:
    // original code
    ip_rt_put(rt);
    out_free:
    if (free)
        kfree(ipc.opt);
    if (!err)
        return len;
    /*
     * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space.  Reporting
     * ENOBUFS might not be good (it's not tunable per se), but otherwise
     * we don't have a good statistic (IpOutDiscards but it can be too many
     * things).  We could add another new stat but at least for now that
     * seems like overkill.
     */
    if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
        UDP_INC_STATS(sock_net(sk),
                      UDP_MIB_SNDBUFERRORS, is_udplite);
    }
    return err;

    do_confirm:
    if (msg->msg_flags & MSG_PROBE)
        dst_confirm_neigh(&rt->dst, &fl4->daddr);
    if (!(msg->msg_flags & MSG_PROBE) || len)
        goto back_from_confirm;
    err = 0;
    goto out;
}