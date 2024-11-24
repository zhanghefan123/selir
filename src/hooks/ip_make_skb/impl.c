#include "hooks/ip_make_skb/ip_make_skb.h"

int path_validation_setup_cork(struct sock *sk, struct inet_cork *cork, struct ipcm_cookie *ipc, struct rtable **rtp){
    struct ip_options_rcu *opt;
    struct rtable *rt;

    rt = *rtp;
    if (unlikely(!rt))
        return -EFAULT;

    /*
     * setup for corking.
     */
    //    因为我们不打算将选项放入, 所以这里就当选项 opt 不存在
    //    -----------------------------------------------------------------------------
    //    opt = ipc->opt;
    //    if (opt) {
    //        if (!cork->opt) {
    //            cork->opt = kmalloc(sizeof(struct ip_options) + 40,
    //                                sk->sk_allocation);
    //            if (unlikely(!cork->opt))
    //                return -ENOBUFS;
    //        }
    //        memcpy(cork->opt, &opt->opt, sizeof(struct ip_options) + opt->opt.optlen);
    //        cork->flags |= IPCORK_OPT;
    //        cork->addr = ipc->addr;
    //    }
    //    -----------------------------------------------------------------------------

    cork->fragsize = ip_sk_use_pmtu(sk) ?
                     dst_mtu(&rt->dst) : READ_ONCE(rt->dst.dev->mtu);

    if (!inetdev_valid_mtu(cork->fragsize))
        return -ENETUNREACH;

    cork->gso_size = ipc->gso_size;

    cork->dst = &rt->dst;
    /* We stole this route, caller should not release it. */
    *rtp = NULL;

    cork->length = 0;
    cork->ttl = ipc->ttl;
    cork->tos = ipc->tos;
    cork->mark = ipc->sockc.mark;
    cork->priority = ipc->priority;
    cork->transmit_time = ipc->sockc.transmit_time;
    cork->tx_flags = 0;
    sock_tx_timestamp(sk, ipc->sockc.tsflags, &cork->tx_flags);

    return 0;
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
struct sk_buff *path_validation_make_skb(struct sock *sk,
                                         struct flowi4 *fl4,
                                         int getfrag(void *from, char *to, int offset,
                                                     int len, int odd, struct sk_buff *skb),
                                         void *from, int length, int transhdrlen,
                                         struct ipcm_cookie *ipc, struct rtable **rtp,
                                         struct inet_cork *cork, unsigned int flags) {
    struct sk_buff_head queue;
    int err;

    if (flags & MSG_PROBE)
        return NULL;

    __skb_queue_head_init(&queue);

    cork->flags = 0;
    cork->addr = 0;
    cork->opt = NULL;
    err = path_validation_setup_cork(sk, cork, ipc, rtp);
    if (err)
        return ERR_PTR(err);

    err = __ip_append_data(sk, fl4, &queue, cork,
                           &current->task_frag, getfrag,
                           from, length, transhdrlen, flags);
    if (err) {
        __ip_flush_pending_frames(sk, &queue, cork);
        return ERR_PTR(err);
    }

    return __ip_make_skb(sk, fl4, &queue, cork);
}
