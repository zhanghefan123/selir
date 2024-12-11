#include "structure/namespace/namespace.h"
#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "hooks/network_layer/ipv4/ip_local_deliver/ip_local_deliver.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"
#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"
#include <net/inet_ecn.h>
#include <linux/inetdevice.h>

int selir_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev){
    // 1. 初始化变量
    struct net* net = dev_net(dev);
    struct SELiRHeader* selir_header = selir_hdr(skb);
    struct PathValidationStructure* pvs = get_pvs_from_ns(net);
    int process_result;
    // 2. 进行消息的打印
    PRINT_SELIR_HEADER(selir_header);
    // 3. 进行初级的校验
    skb = selir_rcv_validate(skb, net);
    if (NULL == skb)
    {
        LOG_WITH_PREFIX("validation failed");
        return 0;
    }
    // 4. 进行实际的转发
    process_result = selir_forward_packets(skb, pvs, net, orig_dev);
    // 5. 判断是否需要上层提交或者释放
    if(NET_RX_SUCCESS == process_result) {
        LOG_WITH_PREFIX("local deliver");
        __be32 receive_interface_address = orig_dev->ip_ptr->ifa_list->ifa_address;
        pv_local_deliver(skb, selir_header->protocol,
                         receive_interface_address);
        return 0;
    } else {
        // 5.2 进行数据包的释放
        LOG_WITH_PREFIX("drop packet");
        kfree_skb_reason(skb, SKB_DROP_REASON_IP_INHDR);
        return 0;
    }
}


struct sk_buff* selir_rcv_validate(struct sk_buff* skb, struct net* net){
    // 获取头部
    const struct SELiRHeader *selir_header;
    // 丢包的原因
    int drop_reason;
    // 总的长度
    u32 len;

    // 进行 pkt_type 的设置 (由于设置的是 BROADCAST_MAC 所以这里不行)
    // 1. PACKET_HOST 代表目的地是本机
    // 2. PACKET_OTHERHOST 代表目的地是其他主机
    skb->pkt_type = PACKET_HOST;

    /* When the interface is in promisc. mode, drop all the crap
     * that it receives, do not try to analyse it
     * 如果是其他主机，那么直接丢
     */
    if (skb->pkt_type == PACKET_OTHERHOST) {
        dev_core_stats_rx_otherhost_dropped_inc(skb->dev);
        drop_reason = SKB_DROP_REASON_OTHERHOST;
        goto drop;
    }

    __IP_UPD_PO_STATS(net, IPSTATS_MIB_IN, skb->len);

    skb = skb_share_check(skb, GFP_ATOMIC);
    if (!skb) {
        __IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
        goto out;
    }

    drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;

    // 确保存在足够的空间
    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        goto inhdr_error;

    // 解析网络层首部
    selir_header = selir_hdr(skb);

    /*
     *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
     *
     *	Is the datagram acceptable?
     *
     *	1.	Length at least the size of an ip header
     *	2.	Version of 4
     *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
     *	4.	Doesn't have a bogus length
     */

    BUILD_BUG_ON(IPSTATS_MIB_ECT1PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_1);
    BUILD_BUG_ON(IPSTATS_MIB_ECT0PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_0);
    BUILD_BUG_ON(IPSTATS_MIB_CEPKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_CE);
    __IP_ADD_STATS(net,
                   IPSTATS_MIB_NOECTPKTS + (selir_header->tos & INET_ECN_MASK),
                   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

    if (!pskb_may_pull(skb, selir_header->hdr_len))
        goto inhdr_error;

    selir_header = selir_hdr(skb);

    // 如果校验和不正确的话, goto csum_error
    if (unlikely(ip_fast_csum((u8 *)selir_header, selir_header->hdr_len / 4)))
    {
        LOG_WITH_PREFIX("csum error");
        goto csum_error;
    }


    // 检查长度是否是合法的
    // --------------------------------------------------------
    // 获取 (网络层 + 传输层 + 应用层) 的总长度
    len = ntohs(selir_header->tot_len);
    if (skb->len < len) {
        drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
        __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
        goto drop;
    } else if (len < (selir_header->hdr_len))
        goto inhdr_error;
    // --------------------------------------------------------

    /* Our transport medium may have padded the buffer out. Now we know it
     * is IP we can trim to the true length of the frame.
     * Note this now means skb->len holds ntohs(iph->tot_len).
     */
    if (pskb_trim_rcsum(skb, len)) {
        __IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
        goto drop;
    }

    selir_header = selir_hdr(skb);

    // 指向正确的传输层的头部
    skb->transport_header = skb->network_header + selir_header->hdr_len;

    /* Remove any debris in the socket control block */
    memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
    IPCB(skb)->iif = skb->skb_iif;

    /* Must drop socket now because of tproxy. */
    if (!skb_sk_is_prefetched(skb))
        skb_orphan(skb);

    return skb;

    csum_error:
    drop_reason = SKB_DROP_REASON_IP_CSUM;
    __IP_INC_STATS(net, IPSTATS_MIB_CSUMERRORS);
    inhdr_error:
    if (drop_reason == SKB_DROP_REASON_NOT_SPECIFIED)
        drop_reason = SKB_DROP_REASON_IP_INHDR;
    __IP_INC_STATS(net, IPSTATS_MIB_INHDRERRORS);
    drop:
    kfree_skb_reason(skb, drop_reason);
    out:
    return NULL;
}

int selir_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev){
    // 1. 初始化变量
    int index;
    int result;
    struct ArrayBasedInterfaceTable* abit = pvs->abit;
    struct SELiRHeader* selir_header = selir_hdr(skb);
    int source = selir_header->source;
    int current_node_id = pvs->node_id;
    unsigned char* pvf_start_pointer = get_selir_pvf_start_pointer(selir_header);
    unsigned char* ppf_start_pointer = get_selir_ppf_start_pointer(selir_header);
    unsigned char* selir_dest_pointer = get_selir_dest_start_pointer(selir_header, selir_header->ppf_len);
    unsigned char* original_bitset = pvs->bloom_filter->bitset;
    pvs->bloom_filter->bitset = ppf_start_pointer;

    // 2. 判断是否需要进行本地的交付
    for(index = 0; index < selir_header->dest_len; index++){
        if(current_node_id == selir_dest_pointer[index]){
            result = NET_RX_SUCCESS;
        } else {
            result = NET_RX_DROP;
        }
    }

    // 2. 准备计算 hmac
    char symmetric_key[20];
    snprintf(symmetric_key, sizeof(symmetric_key), "key-%d-%d", source, current_node_id);
    unsigned char* static_fields_hash = calculate_selir_hash(pvs->hash_api, selir_header);
    unsigned char* hmac_result = calculate_hmac(pvs->hmac_api,
                                                static_fields_hash,
                                                HASH_OUTPUT_LENGTH,
                                                (unsigned char*)symmetric_key,
                                                (int)strlen(symmetric_key));

    // 3. 将 pvf (保持和 opt 相同 16 字节) 和 hmac 进行异或的操作
    int temp;
    for(temp = 0; temp < 2; temp++){
        (*((u64*)pvf_start_pointer + temp)) = (*((u64*)hmac_result + temp)) ^ (*((u64*)(pvf_start_pointer) + temp));
    }

    // 4. 进行 hmac_result 的释放
    kfree(hmac_result);

    // 5. 进行接口表的遍历
    for(index = 0; index < abit->number_of_interfaces; index++){
        struct InterfaceTableEntry* ite = abit->interfaces[index];
        int link_identifier = ite->link_identifier;
        // 进行异或
        (*(int*)(pvf_start_pointer)) = (*(int*)(pvf_start_pointer)) ^ link_identifier;
        // 判断是否在其中
        if(0 == check_element_in_bloom_filter(pvs->bloom_filter, hmac_result, 16)){
            // 进行校验和的重新计算
            selir_send_check(selir_header);
            // 进行数据包的拷贝
            struct sk_buff* copied_skb = skb_copy(skb, GFP_KERNEL);
            // 进行数据包的转发
            pv_packet_forward(copied_skb, ite->interface, current_ns);
        }
        // 再次进行异或就还原了
        (*(int*)(pvf_start_pointer)) = (*(int*)(pvf_start_pointer)) ^ link_identifier;
    }

    // 6. 最后进行哈希和 hmac 的释放
    kfree(static_fields_hash);
    kfree(hmac_result);
    pvs->bloom_filter->bitset = original_bitset;

    return result;
}