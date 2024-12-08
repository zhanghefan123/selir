#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"

void lir_send_check(struct LiRHeader *pvh){
    pvh->check = 0;
    pvh->check = ip_fast_csum((unsigned char *)pvh, pvh->hdr_len / 4);
}

void icing_send_check(struct ICINGHeader* icing_header) {
    icing_header->check = 0;
    icing_header->check = ip_fast_csum((unsigned char*)icing_header, icing_header->hdr_len / 4);
}