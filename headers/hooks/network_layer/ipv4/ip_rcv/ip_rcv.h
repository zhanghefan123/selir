//
// Created by 张贺凡 on 2024/12/3.
//

#ifndef LOADABLE_KERNEL_MODULE_IP_RCV_H
#define LOADABLE_KERNEL_MODULE_IP_RCV_H
#include <net/ip.h>
#include "api/ftrace_hook_api.h"
#include "structure/path_validation_structure.h"
#include "structure/header/lir_header.h"

// 前面还有
// #define NET_RX_SUCCESS		0	/* keep 'em coming, baby */
// #define NET_RX_DROP		1	/* packet dropped */
#define NET_RX_NOTHING 2

int lir_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type *pt, struct net_device* orig_dev);
int icing_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);
int opt_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type *pt, struct net_device* orig_dev);
int selir_rcv(struct sk_buff* skb, struct net_device* dev, struct packet_type* pt, struct net_device* orig_dev);


struct sk_buff* lir_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* icing_rcv_validate(struct sk_buff*skb, struct net* net);
struct sk_buff* opt_rcv_validate(struct sk_buff* skb, struct net* net);
struct sk_buff* selir_rcv_validate(struct sk_buff* skb, struct net* net);

int opt_forward_session_establish_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev);
int opt_forward_data_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev);
int lir_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev);
int icing_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev);
int selir_forward_packets(struct sk_buff* skb, struct PathValidationStructure* pvs, struct net* current_ns, struct net_device* in_dev);


void add_ip_rcv_to_hook(void);
extern struct ftrace_hook hooks[MAXIMUM_SUPPORTED_HOOK_FUNCTIONS];
extern int number_of_hook;
#endif //LOADABLE_KERNEL_MODULE_IP_RCV_H
