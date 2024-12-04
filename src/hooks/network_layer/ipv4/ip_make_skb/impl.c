#include <net/ip.h>
#include <net/icmp.h>
#include "tools/tools.h"
#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"
#include "hooks/network_layer/ipv4/ip_setup_cork/ip_setup_cork.h"
#include "hooks/network_layer/ipv4/ip_append_data/ip_append_data.h"
#include "structure/routing/routing_calc_res.h"
#include "structure/path_validation_header.h"
#include "structure/namespace/namespace.h"

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
    if (err){
        return ERR_PTR(err);
    }
    err = self_defined__ip_append_data(sk, fl4, &queue, cork,
                                       &current->task_frag, getfrag,
                                       from, length, transhdrlen, flags,
                                       rcr);

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
    struct PathValidationHeader *pvh;
    struct PathValidationStructure* pvs = get_pvs_from_ns(net);
    unsigned char* bloom_pointer_start = NULL;
    unsigned char* dest_pointer_start = NULL;

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
    ttl = READ_ONCE(net->ipv4.sysctl_ip_default_ttl);

    // header initialization part
    // ---------------------------------------------------------------------------------------
    pvh = pvh_hdr(skb); // 创建 header (总共9个字段 + 剩余的补充部分)
    pvh->version = 5; // 版本 (字段1)
    pvh->tos = (cork->tos != -1) ? cork->tos : inet->tos; // tos type_of_service (字段2)
    pvh->ttl = ttl; // ttl (字段3)
    pvh->protocol = sk->sk_protocol; // 上层协议 (字段4)
    pvh->frag_off = htons(IP_DF);; // 是否进行分片 (字段5) -> 这里默认设置的是不进行分片操作
    pvh->id = 0; // 进行 id 的设置 (字段6) -> 如果不进行分片的话，那么 id 默认设置为 0
    pvh->check = 0; // 校验和字段 (字段7)
    pvh->source = rcr->source; // 设置源 (字段8)
    pvh->hdr_len = sizeof(struct PathValidationHeader) + rcr->destination_info->number_of_destinations + pvs->bloom_filter->effective_bytes; // 设置数据包总长度 (字段9)
    // tot_len 字段 10 (等待后面进行赋值)
    pvh->bf_len = (int)(pvs->bloom_filter->effective_bytes); // bf 有效字节数 (字段11)
    pvh->dest_len = (int)(rcr->destination_info->number_of_destinations); // 目的的长度 (字段12)
    // ---------------------------------------------------------------------------------------

    // copy destinations
    // ---------------------------------------------------------------------------------------
    dest_pointer_start = (unsigned char*)pvh + sizeof(struct PathValidationHeader);
    int memory_of_destinations = rcr->destination_info->number_of_destinations;
    memcpy(dest_pointer_start, rcr->destination_info->destinations, memory_of_destinations);
    // ---------------------------------------------------------------------------------------

    // copy bloom filter
    // ---------------------------------------------------------------------------------------
    bloom_pointer_start = (unsigned char*)pvh + sizeof(struct PathValidationHeader) + memory_of_destinations;
    memcpy(bloom_pointer_start, rcr->bitset, pvs->bloom_filter->effective_bytes);
    print_memory_in_hex(bloom_pointer_start, pvs->bloom_filter->effective_bytes);
    // ---------------------------------------------------------------------------------------

    skb->priority = (cork->tos != -1) ? cork->priority : sk->sk_priority;
    skb->mark = cork->mark;
    skb->tstamp = cork->transmit_time;
    /*
     * Steal rt from cork.dst to avoid a pair of atomic_inc/atomic_dec
     * on dst refcount
     */
    out:
    return skb;
}
