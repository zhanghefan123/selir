#include "hooks/network_layer/ipv4/ip_send_check/ip_send_check.h"

void pv_send_check(struct LiRHeader *pvh){
    pvh->check = 0;
    pvh->check = ip_fast_csum((unsigned char *)pvh, pvh->hdr_len / 4);
}