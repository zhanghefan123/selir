#include "hooks/network_layer/ipv4/ip_output/ip_output.h"
#include "hooks/network_layer/ipv4/ip_packet_forward/ip_packet_forward.h"

/**
 * 进行数据包的转发
 * @param skb skb
 * @param output_interface 出接口
 * @param current_ns 当前网络命名空间
 * @return
 */
int pv_packet_forward(struct sk_buff* skb, struct net_device* output_interface, struct net* current_ns){
    // 最大数据传输单元
    u32 mtu = READ_ONCE(output_interface->mtu);
    // socket
    struct sock* sk = NULL;
    // reason 原因
    SKB_DR(reason);
    // skb_cow
    skb_cow(skb, LL_RESERVED_SPACE(output_interface->dev));
    // 设置
    skb->dev = output_interface;
    skb->protocol = htons(ETH_P_IP);
    // 当超过 mtu 限制, 需要进行分片
    return pv_finish_output2(current_ns, sk, skb, output_interface);
}