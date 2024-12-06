#include "structure/routing/destination_info.h"

/**
 * 进行目的地址信息的初始化
 * @param number_of_destinations 目的地的数量
 * @return
 */
struct DestinationAndProtocolInfo* initialize_destination_info(int path_validation_protocol, int number_of_destinations){
    struct DestinationAndProtocolInfo* destination_info = (struct DestinationAndProtocolInfo*)kmalloc(sizeof(struct DestinationAndProtocolInfo), GFP_KERNEL);
    destination_info->path_validation_protocol = path_validation_protocol;
    destination_info->number_of_destinations = number_of_destinations;
    destination_info->destinations = (unsigned char*)kmalloc(number_of_destinations, GFP_KERNEL);
    return destination_info;
}

/**
 * 进行目的地址的释放
 * @param destination_info
 */
void free_destination_info(struct DestinationAndProtocolInfo* destination_info){
    if (NULL != destination_info) {
        if (NULL != destination_info->destinations){
            kfree(destination_info->destinations);
            destination_info->destinations = NULL;
        }
        kfree(destination_info);
        destination_info = NULL;
    }
}
