//
// Created by 张贺凡 on 2024/12/9.
//
#include <net/ip.h>
#include "structure/crypto/crypto_structure.h"

#ifndef PATH_VALIDATION_MODULE_OPT_HEADER_H
#define PATH_VALIDATION_MODULE_OPT_HEADER_H
// 定义 SESSION_ID 部分的长度
#define SESSION_ID_LENGTH 16

// first packet 包含的部分
// 1. OptHeader
// 2. SessionId
// 3. Path


// data packet 包含的部分
// 1. OptHeader
// 2. DataHash
// 3. SessionId
// 4. Timestamp
// 5. PVF
// 6. OPVs



struct OptHeader {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 useless: 4, version: 4; // 字段1
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8	version:4,
              ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
    __u8 tos;               // tos 字段2
    __u8 ttl;               // ttl 字段3
    __u8 protocol;          // 上层协议 字段4
    __be16 frag_off;        // 分片相关 字段5
    __u16 id;               // 分片相关 字段6
    __u16 source;           // 源节点编号 字段8
    __u16 dest;             // 目的节点编号 字段9
    __u16 hdr_len;          // 头部长度
    __u16 tot_len;          // 总长度
    __sum16 check;          // 校验和
    __u16 current_path_index;  // 当前路径索引
    unsigned char data[0];  // 额外的部分
};

// PathLength 需要单独一个结构是因为
// 1. first packet 需要
// 2. 其他的 packet 不需要
struct PathLength {
    __u16 data;
};

// 在第一个包建立连接的时候用上的 -> 代表每一跳
struct OptHop {
    __u16 node_id; // 节点 id
    __u16 link_id;  // 链路标识
};


// DataHash
struct DataHash {
    uint64_t first_part; // 8 字节
    uint64_t second_part; // 8 字节
};

// 会话 id
struct SessionID {
    uint64_t first_part;  // 8 字节
    uint64_t second_part; // 8 字节
};

// 时间戳
struct TimeStamp {
    char data[4];
};

// OPT PVF
struct OptPvf {
    char data[16];
};

// OPT OPV
struct OptOpv {
    char data[16];
};

static inline struct OptHeader *opt_hdr(const struct sk_buff *skb) {
    return (struct OptHeader *) skb_network_header(skb);
}

static inline unsigned char* get_first_opt_session_id_pointer(struct OptHeader* opt_header) {
    return (unsigned char*)(opt_header) + sizeof(struct OptHeader);
}

static inline unsigned char *get_opt_path_length_start_pointer(struct OptHeader* opt_header){
    return (unsigned char *) (opt_header) + sizeof(struct OptHeader) + sizeof(struct SessionID);
}

static inline unsigned char *get_opt_path_start_pointer(struct OptHeader *opt_header) {
    return (unsigned char *) (opt_header) + sizeof(struct OptHeader) + sizeof(struct SessionID) + sizeof(struct PathLength);
}

static inline unsigned char *get_opt_pvf_start_pointer(struct OptHeader *opt_header) {
    return (unsigned char *) (opt_header) +
           sizeof(struct OptHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp);
}

static inline unsigned char *get_opt_opv_start_pointer(struct OptHeader *opt_header) {
    return (unsigned char *) (opt_header) +
           sizeof(struct OptHeader) +
           sizeof(struct DataHash) +
           sizeof(struct SessionID) +
           sizeof(struct TimeStamp) +
           sizeof(struct OptPvf);
}

unsigned char *calculate_opt_hash(struct shash_desc *hash_api, struct OptHeader *opt_header);

void PRINT_OPT_HEADER(struct OptHeader *opt_header);

#endif //PATH_VALIDATION_MODULE_OPT_HEADER_H
