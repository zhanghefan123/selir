#include "hooks/udp_sendmsg/udp_sendmsg.h"
#include "hooks/udp_send_skb/udp_send_skb.h"
#include "hooks/ip_make_skb/ip_make_skb.h"
#include "hooks/ip_append_data/ip_append_data.h"
#include "api/test.h"
#include "tools/tools.h"
#include <net/udp.h>
#include <linux/bpf-cgroup.h>
#include <net/udplite.h>

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

    if (len > 0xFFFF)
        return -EMSGSIZE;

    /*
     *	Check the flags.
     */

    if (msg->msg_flags & MSG_OOB) /* Mirror BSD error message compatibility */
        return -EOPNOTSUPP;

    getfrag = is_udplite ? udplite_getfrag : ip_generic_getfrag;

    fl4 = &inet->cork.fl.u.ip4;
    if (up->pending) {
        /*
         * There are pending frames.
         * The socket lock must be held while it's corked.
         */
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
    ulen += sizeof(struct udphdr);

    /*
     *	Get and verify the address.
     */
    if (usin) {
        if (msg->msg_namelen < sizeof(*usin))
            return -EINVAL;
        if (usin->sin_family != AF_INET) {
            if (usin->sin_family != AF_UNSPEC)
                return -EAFNOSUPPORT;
        }

        daddr = usin->sin_addr.s_addr;
        dport = usin->sin_port;
        if (dport == 0)
            return -EINVAL;
    } else {
        if (sk->sk_state != TCP_ESTABLISHED)
            return -EDESTADDRREQ;
        daddr = inet->inet_daddr;
        dport = inet->inet_dport;
        /* Open fast path for connected socket.
           Route will not be used, if at least one option is set.
         */
        connected = 1;
    }

    ipcm_init_sk(&ipc, inet);
    ipc.gso_size = READ_ONCE(up->gso_size);

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
    if (!ipc.opt) {
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

    if (cgroup_bpf_enabled(CGROUP_UDP4_SENDMSG) && !connected) {
        err = BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK(sk,
                                                    (struct sockaddr *) usin, &ipc.addr);
        if (err)
            goto out_free;
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

    saddr = ipc.addr;
    ipc.addr = faddr = daddr;

    if (ipc.opt && ipc.opt->opt.srr) {
        if (!daddr) {
            err = -EINVAL;
            goto out_free;
        }
        faddr = ipc.opt->opt.faddr;
        connected = 0;
    }
    tos = get_rttos(&ipc, inet);
    if (sock_flag(sk, SOCK_LOCALROUTE) ||
        (msg->msg_flags & MSG_DONTROUTE) ||
        (ipc.opt && ipc.opt->opt.is_strictroute)) {
        tos |= RTO_ONLINK;
        connected = 0;
    }

    if (ipv4_is_multicast(daddr)) {
        if (!ipc.oif || netif_index_is_l3_master(sock_net(sk), ipc.oif))
            ipc.oif = inet->mc_index;
        if (!saddr)
            saddr = inet->mc_addr;
        connected = 0;
    } else if (!ipc.oif) {
        ipc.oif = inet->uc_index;
    } else if (ipv4_is_lbcast(daddr) && inet->uc_index) {
        /* oif is set, packet is to local broadcast and
         * uc_index is set. oif is most likely set
         * by sk_bound_dev_if. If uc_index != oif check if the
         * oif is an L3 master and uc_index is an L3 slave.
         * If so, we want to allow the send using the uc_index.
         */
        if (ipc.oif != inet->uc_index &&
            ipc.oif == l3mdev_master_ifindex_by_index(sock_net(sk),
                                                      inet->uc_index)) {
            ipc.oif = inet->uc_index;
        }
    }

    if (connected)
        rt = (struct rtable *) sk_dst_check(sk, 0);

    if (!rt) {
        struct net *net = sock_net(sk);
        __u8 flow_flags = inet_sk_flowi_flags(sk);

        fl4 = &fl4_stack;

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

    if (msg->msg_flags & MSG_CONFIRM)
        goto do_confirm;
    back_from_confirm:

    saddr = fl4->saddr;
    if (!ipc.addr)
        daddr = ipc.addr = fl4->daddr;

    /* Lockless fast path for the non-corking case. */
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

    lock_sock(sk);
    if (unlikely(up->pending)) {
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

    out:
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