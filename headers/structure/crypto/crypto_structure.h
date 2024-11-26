//
// Created by zhf on 2024/11/21.
//

#ifndef LOADABLE_KERNEL_MODULE_CRYPTO_FUNCTION_H
#define LOADABLE_KERNEL_MODULE_CRYPTO_FUNCTION_H
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

// 全局变量
extern unsigned char* hash_output; // hash 输出
extern unsigned char* hmac_output; // hmac 输出

// 生成 hash api
struct shash_desc* generate_hash_api(void);

// 生成 hmac api
struct shash_desc* generate_hmac_api(void);

// 释放 api 所占用的空间
void free_crypto_api(struct shash_desc* crypto_api);

// 进行 api 的测试
void test_crypto_apis(void);

// 进行哈希计算
void calculate_hash(struct shash_desc* hash_api, char* data);

// 进行 hmac 计算
void calculate_hmac(struct shash_desc* hmac_api, char* data, char* key);

// 进行计算结果的释放
void release_hash_and_hmac_output(void);

#endif //LOADABLE_KERNEL_MODULE_CRYPTO_FUNCTION_H
