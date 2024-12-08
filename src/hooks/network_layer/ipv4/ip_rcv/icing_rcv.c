#include "hooks/network_layer/ipv4/ip_rcv/ip_rcv.h"
#include "structure/header/icing_header.h"
#include "structure/namespace/namespace.h"

int icing_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev){
    // 1. 初始化变量
    struct net* net = dev_net(dev);
    struct ICINGHeader* icing_header = icing_hdr(skb);
    struct PathValidationStructure* pvs = get_pvs_from_ns(net);
    int process_result;
    // 2. 进行消息的打印
    PRINT_ICING_HEADER(icing_header);


    // 3. 在没能完整判断之前先进行数据包的释放
    kfree_skb_reason(skb, SKB_DROP_REASON_BPF_CGROUP_EGRESS);
    return 0;
}