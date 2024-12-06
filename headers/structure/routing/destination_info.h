//
// Created by zhf on 2024/11/24.
//

#ifndef LOADABLE_KERNEL_MODULE_DESTINATION_INFO_H
#define LOADABLE_KERNEL_MODULE_DESTINATION_INFO_H
#include <net/ip.h>
struct DestinationAndProtocolInfo {
    int path_validation_protocol;
    int number_of_destinations;
    unsigned char* destinations;
};
struct DestinationAndProtocolInfo* initialize_destination_info(int path_validation_protocol, int number_of_destinations);
void free_destination_info(struct DestinationAndProtocolInfo* destination_info);
#endif //LOADABLE_KERNEL_MODULE_DESTINATION_INFO_H
