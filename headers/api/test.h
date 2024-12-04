//
// Created by zhf on 2024/11/21.
//

#ifndef SELIR_TEST_H
#define SELIR_TEST_H
#include <net/ip.h>
#define IP_NETWORK_TYPE 1
#define LIR_NETWORK_TYPE 2
#define IP_VERSION_NUMBER 4
#define LIR_VERSION_NUMBER 5
void test_apis(void);
int resolve_network_type_from_sk(struct sock* sk);
int resolve_network_type_from_skb(struct sk_buff* skb);
#endif //SELIR_TEST_H
