//
// Created by zhf on 2024/11/24.
//

#ifndef LOADABLE_KERNEL_MODULE_DESTINATION_INFO_H
#define LOADABLE_KERNEL_MODULE_DESTINATION_INFO_H
#include <net/ip.h>
struct DestinationInfo {
    int number_of_destinations;
    int* destinations;
};
struct DestinationInfo* initialize_destination_info(int number_of_destinations);
void free_destination_info(struct DestinationInfo* destination_info);
#endif //LOADABLE_KERNEL_MODULE_DESTINATION_INFO_H
