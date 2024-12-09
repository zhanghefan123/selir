#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"

int opt_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type *pt, struct net_device* orig_dev){
    // 1. 初始化变量
    struct OptHeader* opt_header = opt_hdr(skb);
    // 2. 进行数据包的打印
    PRINT_OPT_HEADER(opt_header);
    // 进行数据包的释放
    kfree_skb_reason(skb, SKB_DROP_REASON_IP_INHDR);
    return 0;
}