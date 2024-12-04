//
// Created by 张贺凡 on 2024/12/3.
//

#ifndef LOADABLE_KERNEL_MODULE_IP_SEND_CHECK_H
#define LOADABLE_KERNEL_MODULE_IP_SEND_CHECK_H
#include <net/ip.h>
#include "structure/path_validation_header.h"
void pv_send_check(struct PathValidationHeader *pvh);
#endif //LOADABLE_KERNEL_MODULE_IP_SEND_CHECK_H
