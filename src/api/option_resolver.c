#include "api/option_resolver.h"

/**
 * 解析选项, 得到目的地
 * type, length, number_of_destinations, destination1, destination2, ...
 * @param opt 选项
 * @return
 */
struct DestinationInfo* resolve_option_for_destination_info(struct ip_options_rcu* opt){
    int index;
    int number_of_destinations = opt->opt.__data[OPTION_START_INDEX];
    struct DestinationInfo* destination_info = initialize_destination_info(number_of_destinations);
    for(index = 1; index <= number_of_destinations; index++){
        destination_info->destinations[index] = opt->opt.__data[OPTION_START_INDEX + index];
    }
    return destination_info;
}