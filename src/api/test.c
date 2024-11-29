#include "api/test.h"
#include "structure/crypto/bloom_filter.h"
#include "structure/crypto/crypto_structure.h"

/**
 * 测试一些 api
 */
void test_apis(void){
    test_bloom_filter();
    test_crypto_apis();
}

/**
 * 判断 socket 是否是 lir socket
 * @param sk socket
 * @return
 */
int resolve_network_type(struct sock* sk){
    if (sock_flag(sk, SOCK_DBG)){
        return LIR_NETWORK_TYPE;
    } else {
        return IP_NETWORK_TYPE;
    }
}