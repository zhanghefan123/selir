#include "tools/tools.h"
#include "structure/crypto/crypto_structure.h"
#include <crypto/ecdh.h>

unsigned char* hash_output = NULL;
unsigned char* hmac_output = NULL;

/**
 * 创建 hash 数据结构
 * @return
 */
struct shash_desc* generate_hash_api(void) {
    struct crypto_shash* tfm;
    struct shash_desc *shash;
    // 使用的 哈希 算法
    tfm = crypto_alloc_shash("sha1", 0, 0);
    if(IS_ERR(tfm)){
        printk(KERN_EMERG "create failed\n");
        return NULL;
    }
    // 进行内存的分配 -> 创建 shash_desc 数据结构
    shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!shash) {
        printk(KERN_EMERG "Failed to allocate shash desc.\n");
        crypto_free_shash(tfm);
        return NULL;
    }
    // 设置使用的哈希算法
    shash->tfm = tfm;
    // 返回创建好的 shash_desc
    return shash;
}

/**
 * 进行哈希的计算
 * @param hash_data_structure hash api
 * @param data 实际的数据
 * @return
 */
void calculate_hash(struct shash_desc* hash_api, char* data){
    // 如果 hash_output 还没有分配内存 -> 那么就进行内存的分配
    if (NULL == hash_output) {
        hash_output =  (unsigned char*) kmalloc(sizeof(unsigned char) * 20, GFP_KERNEL);
    }
    if(crypto_shash_init(hash_api)){
        return;
    }
    if(crypto_shash_update(hash_api, data, strlen(data))){
        return;
    }
    if(crypto_shash_final(hash_api, hash_output)){
        return;
    }
}

/**
 *
 * @param hmac_api hmac api
 * @param data 实际的数据
 * @param key 使用的密钥
 * @return
 */
void calculate_hmac(struct shash_desc* hmac_api, char* data, char* key){
    // 判断是否 hmac_api 为 NULl
    if((NULL == hmac_api) || (NULL == hmac_api -> tfm)){
        return;
    }

    // 判断 hmac 是否已经分配了内存 -> 如果还没有就进行内存的分配
    if(NULL == hmac_output){
        hmac_output = (unsigned char*) kmalloc(sizeof(unsigned char) * 20, GFP_KERNEL);
    }

    // 设置密钥
    if (crypto_shash_setkey(hmac_api->tfm, key, strlen(key))) {
        return;
    }
    // 计算 hmac
    if (crypto_shash_digest(hmac_api, data, strlen(data), hmac_output)) {
        return;
    }
}

/**
 * 创建 MAC 数据结构
 * @return
 */
struct shash_desc* generate_hmac_api(void){
    struct crypto_shash* tfm;
    struct shash_desc *shash;
    // 使用的 mac 算法
    tfm = crypto_alloc_shash("hmac(sha1)", 0, 0);
    if(IS_ERR(tfm)){
        printk(KERN_EMERG "create failed\n");
        return NULL;
    }
    // 进行内存的分配 -> 创建 shash_desc 数据结构
    shash = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!shash) {
        printk(KERN_EMERG "Failed to allocate shash desc.\n");
        crypto_free_shash(tfm);
        return NULL;
    }
    // 设置使用的哈希算法
    shash->tfm = tfm;
    // 返回创建好的 shash_desc
    return shash;
}

/**
 * 进行 hash_api 或者 hmac_api 的释放
 * @param crypto_api
 */
void free_crypto_api(struct shash_desc* crypto_api) {
    if(crypto_api){
        if(crypto_api->tfm){
            LOG_WITH_PREFIX("free tfm");
        }
        LOG_WITH_PREFIX("free crypto api");
        kfree(crypto_api);
    }
}

/**
 * 释放 hash 和 hmac 的输出
 */
void release_hash_and_hmac_output(void){
    if (NULL != hash_output){
        kfree(hash_output);
        hash_output = NULL;
    }
    if (NULL != hmac_output){
        kfree(hmac_output);
        hmac_output = NULL;
    }
}

/**
 * 进行 hash 和 hmac 的测试
 */
void test_crypto_apis(void){
    // 测试哈希函数
    struct shash_desc* hash_api = generate_hash_api();
    calculate_hash(hash_api, "123");
    print_memory_in_hex(hash_output, 20);
    // 测试MAC函数
    struct shash_desc* hmac_api = generate_hmac_api();
    calculate_hmac(hmac_api, "123", "123");
    print_memory_in_hex(hmac_output, 4);
    // 进行内存的释放
    release_hash_and_hmac_output();
    // 进行api的释放
    free_crypto_api(hash_api);
    free_crypto_api(hmac_api);
}