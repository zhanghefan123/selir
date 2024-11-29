//
// Created by zhf on 2024/11/21.
//

#ifndef SELIR_TEST_H
#define SELIR_TEST_H
#include <net/ip.h>
#define IP_NETWORK_TYPE 1
#define LIR_NETWORK_TYPE 2
void test_apis(void);
int resolve_network_type(struct sock* sk);
#endif //SELIR_TEST_H
