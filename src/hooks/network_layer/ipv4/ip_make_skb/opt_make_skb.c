#include "api/test.h"
#include "structure/namespace/namespace.h"
#include "structure/header/opt_header.h"
#include "structure/path_validation_sock_structure.h"
#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"
#include "hooks/network_layer/ipv4/ip_setup_cork/ip_setup_cork.h"
#include "hooks/network_layer/ipv4/ip_append_data/ip_append_data.h"
#include "hooks/network_layer/ipv4/ip_flush_pending_frames/ip_flush_pending_frames.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"

/**
 * 获取数据包的大小 (针对)
 * @param rcr 路由计算结果
 * @param pvs 路径验证数据结构
 * @param sent_first_packet 是否已经发送过了第一个包
 * @return
 */
static int get_opt_header_size(struct RoutingCalcRes *rcr, bool sent_first_packet) {
    struct RoutingTableEntry *rte = rcr->rtes[0];
    int path_length = rte->path_length;
    if (!sent_first_packet) {
        return sizeof(struct OptHeader) + sizeof(struct SessionID) + path_length * sizeof(struct OptHop);
    } else {
        return sizeof(struct OptHeader) +
               sizeof(struct DataHash) +
               sizeof(struct SessionID) +
               sizeof(struct TimeStamp) +
               sizeof(struct OptPvf) +
               sizeof(struct OptOpv) * path_length;
    }
}


static void fill_first_packet_session_id(struct OptHeader* opt_header, struct SessionID session_id){
    // 会话起始 pointer
    unsigned char* session_id_start_pointer = (unsigned char*)(opt_header + sizeof(struct OptHeader));
    // 拷贝 session_id
    memcpy(session_id_start_pointer, &session_id, sizeof(struct SessionID));
}

static void fill_first_packet_path_length(struct OptHeader* opt_header, int path_length) {
    __u16* path_length_start_pointer = (__u16*)(get_opt_path_length_start_pointer(opt_header));
    *path_length_start_pointer = path_length;
}


static void fill_first_packet_opt_path(struct OptHeader* opt_header, struct RoutingTableEntry* rte){
    // 索引
    int index;
    // 路径起始字段
    struct OptHop* path = (struct OptHop*)get_opt_path_start_pointer(opt_header);
    // 路径长度
    int path_length = rte->path_length;
    // 进行路径的设置
    for(index = 0; index < path_length; index++){
        // 当还没到达最后的节点的时候
        if(index != (path_length - 1)){
            path[index].node_id = rte->node_ids[index];
            path[index].link_id = rte->link_identifiers[index+1];
        } else { // 当已经是最后一个节点, 其没有链路标识了
            path[index].node_id = rte->node_ids[index];
            path[index].link_id = 0;
        }
    }
}


/**
 * 填充第一个包的头部
 * @param opt_header opt 首部
 */
static void fill_establish_packet_fields(struct OptHeader *opt_header, struct RoutingTableEntry *rte, struct SessionID session_id) {
    // 进行第一个包的 session_id 的填充
    fill_first_packet_session_id(opt_header, session_id);
    // 进行第一个包的 path_length 的填充
    fill_first_packet_path_length(opt_header, rte->path_length);
    // 进行第一个包的 opt_path 的填充
    fill_first_packet_opt_path(opt_header, rte);
}

/**
 * 填充后续包的头部
 */
static void fill_data_packet_fields(void) {

}

/**
 * 进行 session_id 的计算
 * @return session_id
 */
static unsigned char *calculate_session_id(struct shash_desc *hash_api,
                                           struct RoutingCalcRes *rcr,
                                           struct RoutingTableEntry *rte,
                                           time64_t current_time) {
    unsigned char *data[4] = {
            (unsigned char *) (&(rcr->source)),
            (unsigned char *) (rte->link_identifiers),
            (unsigned char *) (rte->node_ids),
            (unsigned char*)(&current_time)
    };
    int lengths[4] = {
            sizeof(int), // source 的字节数
            sizeof(int) * rte->path_length, // rte->link_identifiers 的字节数
            sizeof(int) * rte->path_length,  // rte->node_ids 的字节数
            sizeof(time64_t) // 时间的大小
    };
    unsigned char *session_id = calculate_hash_from_multiple_segments(hash_api, data, lengths, 4);
    return session_id;
}


static int get_opt_version(bool sent_first_packet){
    if(!sent_first_packet){
        return OPT_ESTABLISH_VERSION_NUMBER;
    } else {
        return OPT_DATA_VERSION_NUMBER;
    }
}


struct sk_buff *self_defined_opt_make_skb(struct sock *sk,
                                          struct flowi4 *fl4,
                                          int getfrag(void *from, char *to, int offset,
                                                      int len, int odd, struct sk_buff *skb),
                                          void *from, int length, int transhdrlen,
                                          struct ipcm_cookie *ipc,
                                          struct inet_cork *cork, unsigned int flags, struct RoutingCalcRes *rcr) {
    struct sk_buff_head queue;
    int err;

    if (flags & MSG_PROBE)
        return NULL;

    __skb_queue_head_init(&queue);

    cork->flags = 0;
    cork->addr = 0;
    cork->opt = NULL;
    err = self_defined_ip_setup_cork(sk, cork, ipc, rcr);
    if (err) {
        return ERR_PTR(err);
    }

    // 判断是否发送了第一个数据包
    // --------------------------------------------------
    bool sent_first_packet;
    if(NULL == sk->path_validation_sock_structure){
        sent_first_packet = false;
    } else {
        sent_first_packet = true;
    }
    // --------------------------------------------------

    // 进行包头的大小的获取, 不同类型的包不一样
    int opt_header_size = get_opt_header_size(rcr, sent_first_packet);

    err = self_defined__xx_append_data(sk, fl4, &queue, cork,
                                       &current->task_frag, getfrag,
                                       from, length, transhdrlen, flags,
                                       rcr, opt_header_size);

    if (err) {
        __ip_flush_pending_frames(sk, &queue, cork);
        return ERR_PTR(err);
    }

    return self_defined__opt_make_skb(sk, fl4, &queue, cork, rcr, sent_first_packet);
}

struct sk_buff *self_defined__opt_make_skb(struct sock *sk,
                                           struct flowi4 *fl4,
                                           struct sk_buff_head *queue,
                                           struct inet_cork *cork,
                                           struct RoutingCalcRes *rcr,
                                           bool sent_first_packet) {
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct OptHeader *opt_header;
    struct PathValidationStructure *pvs = get_pvs_from_ns(net);
    struct RoutingTableEntry *rte = rcr->rtes[0];

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

    // 头部基本部分填充
    // ---------------------------------------------------------------------------------------
    opt_header = opt_hdr(skb);
    opt_header->version = get_opt_version(sent_first_packet); // 版本 (字段1)
    opt_header->tos = (cork->tos != -1) ? cork->tos : inet->tos; // tos type_of_service (字段2)
    opt_header->ttl = ttl; // ttl (字段3)
    opt_header->protocol = sk->sk_protocol; // 上层协议 (字段4)
    opt_header->frag_off = htons(IP_DF); // 是否进行分片 (字段5) -> 这里默认设置的是不进行分片操作
    opt_header->id = 0; // 进行 id 的设置 (字段6) -> 如果不进行分片的话，那么 id 默认设置为 0
    opt_header->check = 0; // 校验和字段 (字段7)
    opt_header->source = rcr->source; // 设置源 (字段8)
    opt_header->dest = rcr->destination_info->destinations[0]; // 设置目的 (字段9)
    opt_header->hdr_len = get_opt_header_size(rcr, sent_first_packet); // 设置数据包总长度 (字段10)
    opt_header->tot_len = htons(skb->len);// tot_len 字段 11 (等待后面进行赋值)
    opt_header->current_path_index = 0; // 当前的索引 (字段12)
    // ---------------------------------------------------------------------------------------



    // 计算 session_id -> 利用 source / link_identifiers / node_ids / timestamp
    // ---------------------------------------------------------------------------------------
    struct SessionID session_id;
    if(!sent_first_packet){
        time64_t current_time_stamp = ktime_get_seconds(); // 进行当前时间的获取
        unsigned char *hash_value = calculate_session_id(pvs->hash_api, rcr, rte, current_time_stamp); // 这里的 session_id 是 20 字节的, 实际只需要 16 字节
        memcpy(&session_id, hash_value, SESSION_ID_LENGTH);
        kfree(hash_value);
    } else {
        session_id = ((struct PathValidationSockStructure*)(sk->path_validation_sock_structure))->session_id; // 从 socket 之中直接拿到 session_id
    }
    // ---------------------------------------------------------------------------------------



    // 头部后续部分初始化
    // ---------------------------------------------------------------------------------------
    // 1. 如果尚未发送第一个包
    if (!sent_first_packet) {
        fill_establish_packet_fields(opt_header, rcr->rtes[0], session_id);
    } else { // 2. 如果已经发送第一个包
        fill_data_packet_fields();
    }
    // ---------------------------------------------------------------------------------------



    // 等待一切就绪后计算 check
    opt_send_check(opt_header);
    skb->priority = (cork->tos != -1) ? cork->priority : sk->sk_priority;
    skb->mark = cork->mark;
    skb->tstamp = cork->transmit_time;
    skb->protocol = htons(ETH_P_IP);

    // 当发送完成之后修改 sent_first_packet 的状态
    // 本来下面的代码是想放在 opt_make_skb 之后的, 但是由于要计算 session_id 还是算了
    // ------------------------------------------------------------------------------
    if (NULL == sk->path_validation_sock_structure) {
        // 进行结构的初始化
        struct PathValidationSockStructure *pvss = init_pvss();
        pvss->sent_first_packet = true;
        pvss->session_id = session_id;
        sk->path_validation_sock_structure = (void *) (pvss);
    }
    // ------------------------------------------------------------------------------

    out:
    return skb;
}