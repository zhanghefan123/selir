#include "tools/tools.h"
#include "structure/crypto_structure.h"

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
 * 哈希 data
 * @param hash_data_structure hash api
 * @param data
 * @return
 */
unsigned char* calculate_hash(struct shash_desc* hash_api, char* data){
    unsigned char* output = (unsigned char*) kmalloc(sizeof(unsigned char) * 20, GFP_KERNEL);
    if(crypto_shash_init(hash_api)){
        return NULL;
    }
    if(crypto_shash_update(hash_api, data, strlen(data))){
        return NULL;
    }
    if(crypto_shash_final(hash_api, output)){
        return NULL;
    }
    return output;
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
void free_crypto_apis(struct shash_desc* crypto_api) {
    if(crypto_api){
        if(crypto_api->tfm){
            LOG_WITH_PREFIX("free tfm");
        }
        LOG_WITH_PREFIX("free crypto api");
        kfree(crypto_api);
    }
}

void test_crypto_apis(void){
    // ----------------------------------------- test hash function -----------------------------------------
    struct shash_desc* hash_api = generate_hash_api();
    unsigned char* hash_result = calculate_hash(hash_api, "123");
    print_hash_or_hmac_result(hash_result, 20);
    kfree(hash_result);
    // ----------------------------------------- test hash function -----------------------------------------
    unsigned char* hmac_result = calculate_hmac(lir_data_structure->hmac_data_structure, "123", "123");
    print_hash_or_hmac_result(hmac_result, 4);
    kfree(hmac_result);
}