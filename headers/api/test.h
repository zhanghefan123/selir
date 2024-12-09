//
// Created by zhf on 2024/11/21.
//

#ifndef PVM_TEST_H
#define PVM_TEST_H
#include <net/ip.h>
// 定义的网络类型
#define NORMAL_SOCKET_TYPE 1
#define LINK_IDENTIFIED_SOCKET_TYPE 2

// 定义的协议类型
#define IP_VERSION_NUMBER 4
#define LIR_VERSION_NUMBER 5
#define ICING_VERSION_NUMBER 6
// OPT_VERSION_NUMBER 代表的是从上面 socket 指定的版本号
#define OPT_VERSION_NUMBER 7
#define OPT_ESTABLISH_VERSION_NUMBER 8
#define OPT_DATA_VERSION_NUMBER 9
#define SELIR_VERSION_NUMBER 10

void test_apis(void);
int resolve_socket_type(struct sock* sk);
#endif //PVM_TEST_H
