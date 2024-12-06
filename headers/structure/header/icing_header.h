//
// Created by zhf on 2024/12/6.
//

#ifndef PATH_VALIDATION_MODULE_ICING_HEADER_H
#define PATH_VALIDATION_MODULE_ICING_HEADER_H
#include <linux/byteorder/little_endian.h>
#include <net/ip.h>

struct ICINGHeader {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 useless: 4,version: 4; // 字段1
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8	version:4,
              ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
    __u8	tos;            // tos 字段2
    __u8 ttl;               // ttl 字段3
    __u8 protocol;          // 上层协议 字段4
    __be16 frag_off;        // 分片相关 字段5
    __u16 id;               // 分片相关 字段6
    __sum16 check;          // 校验和 字段7
    __u16 source;           // 源节点编号 字段8
    __u16 dest;             // 目的节点编号 字段9
    int hdr_len;            // 头部总长度 字段10
    int tot_len;            // 总的长度 字段11
    unsigned char data[0];  // 额外的部分 (这里是指的 bf 的 bitarray)
};

struct NodeIdAndTag {
    unsigned char data[24]; // 20 byte node id and 4 bytes tag
};

struct Expire {
    unsigned char data[2]; // 2 bytes expire
};

struct ProofAndHardner {
    unsigned char data[16]; // 14 bytes proof and 2 bytes hardener
};


static inline struct ICINGHeader *icing_hdr(const struct sk_buff* skb) {
    return (struct ICINGHeader *) skb_network_header(skb);
}

#endif //PATH_VALIDATION_MODULE_ICING_HEADER_H
