//
// Created by zhf on 2024/11/24.
//

#ifndef LOADABLE_KERNEL_MODULE_PATH_VALIDATION_HEADER_H
#define LOADABLE_KERNEL_MODULE_PATH_VALIDATION_HEADER_H

#include <uapi/linux/types.h>
#include <linux/byteorder/little_endian.h>
#include <net/ip.h>


struct PathValidationHeader {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 useless: 4,
            version: 4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8	version:4,
              ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
    __u8 ttl;            // ttl
    __u8 protocol;          // 上层协议
    __u16 id;               // 分片相关
    __be16 frag_off;       // 分片相关
    __sum16 check;          // 校验和
    __u16 source;           // 源节点编号
    int bf_len;             //  布隆过滤器长度
    unsigned char data[0];   // 额外的部分
};

static inline struct PathValidationHeader *pvh_hdr(const struct sk_buff *skb) {
    return (struct PathValidationHeader *) skb_network_header(skb);
}

#endif //LOADABLE_KERNEL_MODULE_PATH_VALIDATION_HEADER_H
