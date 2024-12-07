#include "structure/header/icing_header.h"
#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"
#include "hooks/network_layer/ipv4/ip_setup_cork/ip_setup_cork.h"
#include "hooks/network_layer/ipv4/ip_append_data/ip_append_data.h"
#include "hooks/network_layer/ipv4/ip_flush_pending_frames/ip_flush_pending_frames.h"
#include "structure/namespace/namespace.h"
#include "structure/crypto/crypto_structure.h"
#include "api/test.h"

/**
 *
 * SAT1 --LID1--> SAT2 --LID2--> SAT3 --LID3--> SAT4 三跳的路径
   length_of_path = 3
   path[0] node_id = SAT2 link_identifier = L2 current_path_index=0
   path[1] node_id = SAT3 link_identifier = L3 current_path_index=1
   path[2] node_id = SAT4 current_path_index = 2
 * @param rcr
 * @return
 */
static int get_icing_header_size(struct RoutingCalcRes *rcr) {
    // 1. 取出只可能存在的一条路由
    struct RoutingTableEntry *rte = rcr->rtes[0];
    // 2. 进行返回
    return (int) (sizeof(struct ICINGHeader))
           + (int) (rte->path_length * sizeof(struct NodeIdAndTag))
           + (int) (rte->path_length * sizeof(struct Expire))
           + (int) (rte->path_length * sizeof(struct ProofAndHardner));
}

/**
 * 进行 icing 字段的填充
 * SAT1 --LID1--> SAT2 --LID2--> SAT3 --LID3--> SAT4 三跳的路径
   length_of_path = 3
   path[0] node_id = SAT2 link_identifier = L2 current_path_index=0
   path[1] node_id = SAT3 link_identifier = L3 current_path_index=1
   path[2] node_id = SAT4 current_path_index = 2
   功能: 拷贝 icing 路径
   @param icing_header icing 头部
 * @param current_ns 当前的网络命名空间
 * @param rte 路由表项
 */
static void fill_icing_path(struct ICINGHeader* icing_header, struct RoutingTableEntry* rte){
    // 索引
    int index;
    // 路径长度
    int path_length = rte->path_length;
    // 起始指针
    unsigned char* path_start_pointer = (unsigned char*)(icing_header) + sizeof(struct ICINGHeader);
    // 进行路径部分内存分配以及填充
    // -------------------------------------------------------------------------------------
    struct NodeIdAndTag* path = (struct NodeIdAndTag*)path_start_pointer;
    for(index = 0; index < path_length; index++){
        // 如果没有遍历到最后一个分段
        if(index != (path_length - 1)) {
            path[index].node_id = rte->node_ids[index];
            path[index].node_id = rte->link_identifiers[index+1];
        } else {
            path[index].node_id = rte->node_ids[index];
        }
    }
    // -------------------------------------------------------------------------------------
}

/**
 * 功能: 进行 icing 验证字段的填充
 */
static void fill_icing_validation(struct ICINGHeader* icing_header, struct RoutingTableEntry* rte, struct PathValidationStructure* pvs){
    // 索引
    int index;
    // 当前节点 id
    int current_node_id = pvs->node_id;
    // 路径长度
    int path_length = rte->path_length;
    // 路径部分的内存
    int path_memory = (int)(sizeof(struct NodeIdAndTag)) * path_length;
    // expire 部分的内存
    int expire_memory = (int)(sizeof(struct Expire)) * path_length;
    // 起始指针
    unsigned char* validation_start_pointer = (unsigned char*)(icing_header) + path_memory + expire_memory;
    // 进行路径部分内存分配以及填充
    // -------------------------------------------------------------------------------------
    // 1. 先进行静态哈希的计算
    calculate_hash(pvs->hash_api, icing_header, sizeof(struct ICINGHeader));


    struct ProofAndHardner* proof_list = (struct ProofAndHardner*)(validation_start_pointer);
    for(index = 0; index < path_length; index++){
        // 拿到中间节点的 id
        int on_path_node_id = rte->node_ids[index];
        // 准备创建密钥
        char symmetric_key[20];
        snprintf(symmetric_key, sizeof(symmetric_key), "key-%d-%d", current_node_id, on_path_node_id);
        // 准备计算 hash 以及 hmac

    }
    // -------------------------------------------------------------------------------------
}

struct sk_buff *self_defined_icing_make_skb(struct sock *sk,
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
    int icing_header_size = get_icing_header_size(rcr);
    err = self_defined__xx_append_data(sk, fl4, &queue, cork,
                                       &current->task_frag, getfrag,
                                       from, length, transhdrlen, flags,
                                       rcr, icing_header_size);
    if (err) {
        __ip_flush_pending_frames(sk, &queue, cork);
        return ERR_PTR(err);
    }

    return self_defined__icing_make_skb(sk, fl4, &queue, cork, rcr);
}


struct sk_buff* self_defined__icing_make_skb(struct sock *sk,
                                             struct flowi4 *fl4,
                                             struct sk_buff_head *queue,
                                             struct inet_cork *cork,
                                             struct RoutingCalcRes *rcr){
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct ICINGHeader *icing_header;
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
    icing_header = icing_hdr(skb); // 创建 header (总共9个字段 + 剩余的补充部分)
    icing_header->version = ICING_VERSION_NUMBER; // 版本 (字段1)
    icing_header->tos = (cork->tos != -1) ? cork->tos : inet->tos; // tos type_of_service (字段2)
    icing_header->ttl = ttl; // ttl (字段3)
    icing_header->protocol = sk->sk_protocol; // 上层协议 (字段4)
    icing_header->frag_off = htons(IP_DF);; // 是否进行分片 (字段5) -> 这里默认设置的是不进行分片操作
    icing_header->id = 0; // 进行 id 的设置 (字段6) -> 如果不进行分片的话，那么 id 默认设置为 0
    icing_header->check = 0; // 校验和字段 (字段7)
    icing_header->source = rcr->source; // 设置源 (字段8)
    icing_header->dest = rcr->destination_info->destinations[0]; // 设置目的 (字段9)
    icing_header->hdr_len = get_icing_header_size(rcr); // 设置数据包总长度 (字段10)
    // tot_len 字段 11 (等待后面进行赋值)
    icing_header->length_of_path = rcr->rtes[0]->path_length; // 设置长度 (字段12)
    icing_header->current_path_index = 0; // 当前的索引 (字段13)
    // ---------------------------------------------------------------------------------------
    fill_icing_path(icing_header, rcr->rtes[0]);
}