#include <net/ip.h>
#include <net/icmp.h>
#include "tools/tools.h"
#include "hooks/ip_make_skb/ip_make_skb.h"
#include "hooks/ip_setup_cork/ip_setup_cork.h"
#include "hooks/ip_append_data/ip_append_data.h"
#include "structure/routing/routing_calc_res.h"
#include "structure/path_validation_header.h"


char *ip_idents_str = "ip_idents";
char *ip_tstamps_str = "ip_tstamps";
char *ip_options_build_str = "ip_options_build";
char *icmp_out_count_str = "icmp_out_count";

static atomic_t *ip_idents __read_mostly;
static u32 *ip_tstamps __read_mostly;
asmlinkage void (*orig_ip_options_build)(struct sk_buff *skb, struct ip_options *opt, __be32 daddr, struct rtable *rt);
asmlinkage void (*orig_icmp_out_count)(struct net *net, unsigned char type);


/**
 * 进行 ip_make_skb 内部所引用的函数的解析
 * @return 返回是否成功进行了所有的函数的地址的解析
 */
bool resolve_ip_make_skb_inner_functions_address(void) {
    LOG_WITH_EDGE("start to resolve path_validation_make_skb inner functions address");
    // 解析结果
    bool resolve_result;
    // 所有的待初始化的函数的函数指针过程的数组
    void *functions[4];
    char *function_names[4] = {
            ip_idents_str,
            ip_tstamps_str,
            ip_options_build_str,
            icmp_out_count_str,
    };
    resolve_result = resolve_functions_addresses(functions, function_names, 4);
    ip_idents = functions[0];
    ip_tstamps = functions[1];
    orig_ip_options_build = functions[2];
    orig_icmp_out_count = functions[3];
    LOG_WITH_EDGE("end to resolve path_validation_make_skb inner functions address");
    return resolve_result;
}

/**
 * 进行 cork 的 release
 * @param cork
 */
static void ip_cork_release(struct inet_cork *cork) {
    cork->flags &= ~IPCORK_OPT;
    kfree(cork->opt);
    cork->opt = NULL;
}

static void __ip_flush_pending_frames(struct sock *sk,
                                      struct sk_buff_head *queue,
                                      struct inet_cork *cork) {
    struct sk_buff *skb;

    while ((skb = __skb_dequeue_tail(queue)) != NULL)
        kfree_skb(skb);

    ip_cork_release(cork);
}

static inline int ip_select_ttl(struct inet_sock *inet, struct dst_entry *dst) {
    int ttl = inet->uc_ttl;

    if (ttl < 0)
        ttl = ip4_dst_hoplimit(dst);
    return ttl;
}

static void ip_copy_addrs(struct iphdr *iph, const struct flowi4 *fl4) {
    BUILD_BUG_ON(offsetof(typeof(*fl4), daddr) !=
                         offsetof(typeof(*fl4), saddr) + sizeof(fl4->saddr));

    iph->saddr = fl4->saddr;
    iph->daddr = fl4->daddr;
}


/**
 * 进行路径校验数据包的构建
 * @param sk
 * @param fl4
 * @param getfrag
 * @param from
 * @param length
 * @param transhdrlen
 * @param ipc
 * @param rtp
 * @param cork
 * @param flags
 * @return
 */
struct sk_buff *self_defined_ip_make_skb(struct sock *sk,
                                         struct flowi4 *fl4,
                                         int getfrag(void *from, char *to, int offset,
                                                     int len, int odd, struct sk_buff *skb),
                                         void *from, int length, int transhdrlen,
                                         struct ipcm_cookie *ipc,
                                         struct inet_cork *cork, unsigned int flags,
                                         struct RoutingCalcRes* rcr) {
    struct sk_buff_head queue;
    int err;

    if (flags & MSG_PROBE)
        return NULL;

    __skb_queue_head_init(&queue);

    cork->flags = 0;
    cork->addr = 0;
    cork->opt = NULL;
    err = self_defined_ip_setup_cork(sk, cork, ipc, rcr);
    if (err)
        return ERR_PTR(err);

    err = self_defined__ip_append_data(sk, fl4, &queue, cork,
                                       &current->task_frag, getfrag,
                                       from, length, transhdrlen, flags);
    if (err) {
        __ip_flush_pending_frames(sk, &queue, cork);
        return ERR_PTR(err);
    }

    return self_defined__ip_make_skb(sk, fl4, &queue, cork, rcr);
}


/**
 * 进行 ip 层的构建
 * @param sk 套接字
 * @param fl4 流
 * @param queue 队列
 * @param cork cork 缓存信息
 * @return
 */
struct sk_buff *self_defined__ip_make_skb(struct sock *sk,
                                          struct flowi4 *fl4,
                                          struct sk_buff_head *queue,
                                          struct inet_cork *cork,
                                          struct RoutingCalcRes* rcr) {
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct ip_options *opt = NULL;
    struct PathValidationHeader *pvh;

    __be16 df = 0;
    __u8 ttl;

    skb = __skb_dequeue(queue);
    if (!skb)
        goto out;
    tail_skb = &(skb_shinfo(skb)->frag_list);

    /* move skb->data to ip header from ext header */
    if (skb->data < skb_network_header(skb))
        __skb_pull(skb, skb_network_offset(skb));
    while ((tmp_skb = __skb_dequeue(queue)) != NULL) {
        __skb_pull(tmp_skb, skb_network_header_len(skb));
        *tail_skb = tmp_skb;
        tail_skb = &(tmp_skb->next);
        skb->len += tmp_skb->len;
        skb->data_len += tmp_skb->len;
        skb->truesize += tmp_skb->truesize;
        tmp_skb->destructor = NULL;
        tmp_skb->sk = NULL;
    }

    /* Unless user demanded real pmtu discovery (IP_PMTUDISC_DO), we allow
     * to fragment the frame generated here. No matter, what transforms
     * how transforms change size of the packet, it will come out.
     */
    skb->ignore_df = ip_sk_ignore_df(sk);

    /* DF bit is set when we want to see DF on outgoing frames.
     * If ignore_df is set too, we still allow to fragment this frame
     * locally. */
    if (inet->pmtudisc == IP_PMTUDISC_DO ||
        inet->pmtudisc == IP_PMTUDISC_PROBE ||
        (skb->len <= rcr->output_interface->mtu))
        df = htons(IP_DF);
    ttl = READ_ONCE(net->ipv4.sysctl_ip_default_ttl);

    pvh = pvh_hdr(skb); // 创建 header
    pvh->version = 5; // 版本
    pvh->protocol = sk->sk_protocol; // 上层协议
    pvh->frag_off = df; // 是否进行分片
    pvh->ttl = ttl; // ttl
    pvh->source = rcr->source; // 设置源
    pvh->bf_len = rcr->pvs->bloom_filter->effective_bytes; // bf 有效字节数


    ip_select_ident(net, skb, sk);

    if (opt) {
        iph->ihl += opt->optlen >> 2;
        orig_ip_options_build(skb, opt, cork->addr, rt);
    }

    skb->priority = (cork->tos != -1) ? cork->priority : sk->sk_priority;
    skb->mark = cork->mark;
    skb->tstamp = cork->transmit_time;
    /*
     * Steal rt from cork.dst to avoid a pair of atomic_inc/atomic_dec
     * on dst refcount
     */
    cork->dst = NULL;
    skb_dst_set(skb, &rt->dst);

    if (iph->protocol == IPPROTO_ICMP)
        orig_icmp_out_count(net, ((struct icmphdr *) skb_transport_header(skb))->type);

    ip_cork_release(cork);
    out:
    return skb;
}
