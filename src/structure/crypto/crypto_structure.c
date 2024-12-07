#include "tools/tools.h"
#include "structure/crypto/crypto_structure.h"

// 如果想要采用全局的变量是不行的
//unsigned char* hash_output = NULL;
//unsigned char* hmac_output = NULL;

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
unsigned char* calculate_hash(struct shash_desc* hash_api, char* data, int length){
    // 如果 hash_output 还没有分配内存 -> 那么就进行内存的分配
    unsigned char* hash_output = (unsigned char*) kmalloc(sizeof(unsigned char) * 20, GFP_KERNEL);
    if(crypto_shash_init(hash_api)){
        NULL;
    }
    if(crypto_shash_update(hash_api, data, length)){
        NULL;
    }
    if(crypto_shash_final(hash_api, hash_output)){
        NULL;
    }
    return hash_output;
}

/**
 *
 * @param hmac_api hmac api
 * @param data 实际的数据
 * @param key 使用的密钥
 * @param data 的长度
 * @return
 */
unsigned char* calculate_hmac(struct shash_desc* hmac_api, char* data, char* key, int length){
    // 判断是否 hmac_api 为 NULl
    if((NULL == hmac_api) || (NULL == hmac_api -> tfm)){
        return NULL;
    }

    // 进行输出的内存的分配
    unsigned char* hmac_output = (unsigned char*) kmalloc(sizeof(unsigned char) * 20, GFP_KERNEL);

    // 设置密钥
    if (crypto_shash_setkey(hmac_api->tfm, key, strlen(key))) {
        return NULL;
    }
    // 计算 hmac
    if (crypto_shash_digest(hmac_api, data, length, hmac_output)) {
        return NULL;
    }

    return hmac_output;
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
 * 进行 hash 和 hmac 的测试
 */
void test_crypto_apis(void){
    // 测试哈希函数
    struct shash_desc* hash_api = generate_hash_api();
    unsigned char* hash_output = calculate_hash(hash_api, "123", strlen("123"));
    print_memory_in_hex(hash_output, 20);
    // 测试MAC函数
    struct shash_desc* hmac_api = generate_hmac_api();
    unsigned char* hmac_output = calculate_hmac(hmac_api, "123", "123", strlen("123"));
    print_memory_in_hex(hmac_output, 4);
    // 进行api的释放
    free_crypto_api(hash_api);
    free_crypto_api(hmac_api);
    kfree(hash_output);
    kfree(hmac_output);
}