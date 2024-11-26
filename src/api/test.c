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
bool test_if_lir_socket(struct sock* sk){
    return sock_flag(sk, SOCK_DBG);
}