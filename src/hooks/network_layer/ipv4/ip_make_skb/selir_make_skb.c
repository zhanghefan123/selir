#include "api/test.h"
#include "structure/namespace/namespace.h"
#include "structure/routing/routing_calc_res.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"
#include "hooks/network_layer/ipv4/ip_setup_cork/ip_setup_cork.h"
#include "hooks/network_layer/ipv4/ip_append_data/ip_append_data.h"
#include "hooks/network_layer/ipv4/ip_flush_pending_frames/ip_flush_pending_frames.h"

/**
 * 进行 selir 头部的大小的获取
 * selir 头部构造如下 (标准头部) / (pvf_effective_bytes) / (bf_effective_bytes) / dest1 / dest2 ....
 * @param rcr 路由计算结果
 * @param pvs 路径验证结构体
 * @return
 */
static int get_selir_header_size(struct RoutingCalcRes *rcr, struct PathValidationStructure *pvs) {
    return sizeof(struct SELiRHeader) +
           sizeof(struct SELiRPvf) +
           pvs->bloom_filter->bf_effective_bytes +
           rcr->user_space_info->number_of_destinations;
}


struct sk_buff *self_defined_selir_make_skb(struct sock *sk,
                                            struct flowi4 *fl4,
                                            int getfrag(void *from, char *to, int offset,
                                                        int len, int odd, struct sk_buff *skb),
                                            void *from, int length, int transhdrlen,
                                            struct ipcm_cookie *ipc,
                                            struct inet_cork *cork, unsigned int flags, struct RoutingCalcRes *rcr) {
    struct sk_buff_head queue;
    int err;
    struct net *current_ns = sock_net(sk);
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);

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

    int lir_header_size = get_selir_header_size(rcr, pvs);

    err = self_defined__xx_append_data(sk, fl4, &queue, cork,
                                       &current->task_frag, getfrag,
                                       from, length, transhdrlen, flags,
                                       rcr, lir_header_size);

    if (err) {
        __ip_flush_pending_frames(sk, &queue, cork);
        return ERR_PTR(err);
    }

    return self_defined__selir_make_skb(sk, fl4, &queue, cork, rcr);
}

/**
 * 进行 pvf 字段的填充
 * @param selir_header selir 首部
 * @param pvf_length pvf 长度
 */
static void fill_pvf_fields(struct SELiRHeader *selir_header) {
    // 获取 pvf 起始的指针
    unsigned char *pvf_start_pointer = get_selir_pvf_start_pointer(selir_header);
    // 将其置为 0
    memset(pvf_start_pointer, 0, sizeof(struct SELiRPvf));
}

static void fill_ppf_fields(struct SELiRHeader *selir_header,
                            struct RoutingCalcRes *rcr,
                            struct PathValidationStructure *pvs) {
    // 索引
    int index;
    int inner_index;
    // 计算静态字段的哈希
    unsigned char *static_fields_hash = calculate_selir_hash(pvs->hash_api, selir_header);
    // 获取 ppf 起始的指针
    unsigned char *ppf_start_pointer = get_selir_ppf_start_pointer(selir_header);
    // 对称密钥
    char symmetric_key[20];
    // 获取当前节点的 id
    int current_node_id = pvs->node_id;
    // 进行所有的路由条目的遍历 (现在还是只能支持一个 destination)
    unsigned char final_insert_element[16];
    for (index = 0; index < rcr->number_of_routes; index++) {
        // 拿到路由条目 -> 如果是第一条则对应的是 source->primary
        struct RoutingTableEntry *rte = rcr->rtes[index];
        for (inner_index = 0; inner_index < rte->path_length; inner_index++) {
            int intermediate_node = rte->node_ids[index]; // 拿到中间节点
            snprintf(symmetric_key, sizeof(symmetric_key), "key-%d-%d", current_node_id, intermediate_node); // 对称密钥
            unsigned char *hmac_result = calculate_hmac(pvs->hmac_api,
                                                        static_fields_hash,
                                                        HASH_OUTPUT_LENGTH,
                                                        (unsigned char *) symmetric_key,
                                                        (int) (strlen(symmetric_key)));

            // 进行和 hmac 的异或
            int temp;
            for (temp = 0; temp < 4; temp++) {
                (*((u32 *) final_insert_element + temp)) =
                        (*((u32 *) final_insert_element + temp)) ^ (*((u32 *) (hmac_result) + temp));
            }

            // 进行和链路标识的异或
            if (index != rte->path_length - 1) {
                int link_identifier = rte->link_identifiers[index];
                (*(int *) (final_insert_element)) = (*(int *) (final_insert_element)) ^ link_identifier;
            }

            // 将 hmac_result 插入到 bf 之中
            push_element_into_bloom_filter(pvs->bloom_filter, final_insert_element, HMAC_OUTPUT_LENGTH);
            // 进行 hmac_result 的释放
            kfree(hmac_result);
        }
    }
    // 将 bf 复制到 ppf 的位置
    memcpy(ppf_start_pointer, pvs->bloom_filter, pvs->bloom_filter->bf_effective_bytes);
    // 进行 bf 的重置
    reset_bloom_filter(pvs->bloom_filter);
    // 在最后进行静态哈希的释放
    kfree(static_fields_hash);
}

/**
 * 进行目的的填充
 * @param selir_header selir 头部
 * @param ppf_length ppf 长度
 * @param user_space_info 用户空间信息
 */
static void fill_destination_fields(struct SELiRHeader *selir_header,
                                    int ppf_length,
                                    struct UserSpaceInfo *user_space_info) {
    // 索引
    int index;
    // 获取指向目的的指针
    unsigned char *destination_start_pointer = get_selir_dest_start_pointer(selir_header, ppf_length);
    // 进行填充
    for (index = 0; index < user_space_info->number_of_destinations; index++) {
        destination_start_pointer[index] = user_space_info->destinations[index];
    }
}

struct sk_buff *self_defined__selir_make_skb(struct sock *sk, struct flowi4 *fl4,
                                             struct sk_buff_head *queue, struct inet_cork *cork,
                                             struct RoutingCalcRes *rcr) {
    struct sk_buff *skb, *tmp_skb;
    struct sk_buff **tail_skb;
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct SELiRHeader *selir_header;
    struct PathValidationStructure *pvs = get_pvs_from_ns(net);
    unsigned char *bloom_pointer_start = NULL;
    unsigned char *dest_pointer_start = NULL;

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
    selir_header = selir_hdr(skb); // 创建 header
    selir_header->version = SELIR_VERSION_NUMBER; // 版本 (字段1)
    selir_header->tos = (cork->tos != -1) ? cork->tos : inet->tos; // tos type_of_service (字段2)
    selir_header->ttl = ttl; // ttl (字段3)
    selir_header->protocol = sk->sk_protocol; // 上层协议 (字段4)
    selir_header->frag_off = htons(IP_DF); // 是否进行分片 (字段5) -> 这里默认设置的是不进行分片操作
    selir_header->id = 0; // 进行 id 的设置 (字段6) -> 如果不进行分片的话，那么 id 默认设置为 0
    selir_header->check = 0; // 校验和字段 (字段7)
    selir_header->source = rcr->source; // 设置源 (字段8)
    selir_header->hdr_len = get_selir_header_size(rcr, pvs); // 设置数据包头部长度 (字段9)
    selir_header->tot_len = htons(skb->len); // tot_len 字段 10
    selir_header->ppf_len = pvs->bloom_filter->bf_effective_bytes; // ppf 长度
    selir_header->dest_len = rcr->user_space_info->number_of_destinations; // 目的数量
    // ---------------------------------------------------------------------------------------

    // 填充 pvf 字段
    // ---------------------------------------------------------------------------------------
    fill_pvf_fields(selir_header);
    // ---------------------------------------------------------------------------------------

    // 填充 ppf 字段
    // ---------------------------------------------------------------------------------------
    fill_ppf_fields(selir_header, rcr, pvs);
    // ---------------------------------------------------------------------------------------

    // 填充目的字段
    // ---------------------------------------------------------------------------------------
    fill_destination_fields(selir_header,
                            pvs->bloom_filter->bf_effective_bytes,
                            rcr->user_space_info);
    // ---------------------------------------------------------------------------------------

    // 等待一切就绪之后计算 selir_send_check
    // ---------------------------------------------------------------------------------------
    selir_send_check(selir_header);
    skb->priority = (cork->tos != -1) ? cork->priority : sk->sk_priority;
    skb->mark = cork->mark;
    skb->tstamp = cork->transmit_time;
    skb->protocol = htons(ETH_P_IP);

    out:
    return skb;
    // ---------------------------------------------------------------------------------------s
}