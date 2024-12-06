#include "api/option_resolver.h"
#include "tools/tools.h"
/**
 * 解析选项, 得到目的地
 * type, length, number_of_destinations, destination1, destination2, ...
 * @param opt 选项
 * @return
 */
struct DestinationAndProtocolInfo* resolve_opt_for_dest_and_proto_info(struct ip_options_rcu* opt){
    int index;
    int path_validation_protocol = opt->opt.__data[PATH_VALIDATION_PROTOCOL_INDEX];
    int number_of_destinations = opt->opt.__data[NUMBER_OF_DESTINATIONS_INDEX];
    struct DestinationAndProtocolInfo* destination_info = initialize_destination_info(path_validation_protocol, number_of_destinations);
    for(index = 0; index < number_of_destinations; index++){
        destination_info->destinations[index] = opt->opt.__data[DESTINATIONS_START_INDEX + index];
    }
    return destination_info;
}