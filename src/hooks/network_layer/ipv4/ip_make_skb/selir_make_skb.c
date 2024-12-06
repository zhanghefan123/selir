#include "hooks/network_layer/ipv4/ip_make_skb/ip_make_skb.h"

struct sk_buff *self_defined_selir_make_skb(struct sock *sk,
                                          struct flowi4 *fl4,
                                          int getfrag(void *from, char *to, int offset,
                                                      int len, int odd, struct sk_buff *skb),
                                          void *from, int length, int transhdrlen,
                                          struct ipcm_cookie *ipc,
                                          struct inet_cork *cork, unsigned int flags, struct RoutingCalcRes *rcr) {
    return NULL;
}