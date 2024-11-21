#include "api/test.h"
#include "structure/bloom_filter.h"
#include "structure/crypto_structure.h"

void test_apis(void){
    test_bloom_filter();
    test_crypto_apis();
}