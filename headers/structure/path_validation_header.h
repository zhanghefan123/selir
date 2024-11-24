//
// Created by zhf on 2024/11/24.
//

#ifndef LOADABLE_KERNEL_MODULE_PATH_VALIDATION_HEADER_H
#define LOADABLE_KERNEL_MODULE_PATH_VALIDATION_HEADER_H
#include <uapi/linux/types.h>
#include <linux/byteorder/little_endian.h>
#include <net/ip.h>

struct PVFField {
    __u16 len;
    unsigned char data[0];
};

struct PPFField {
    __u16 len;
    unsigned char data[0];
};

struct PathValidationHeader {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8	useless:4,
            version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8	version:4,
  		    ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
    __u8 protocol;          // 上层协议
    __u16 id;               // 分片相关
    __be16	frag_off;       // 分片相关
    __sum16	check;          // 校验和
    __u16 header_len;       // 头部长度
    __u16 total_len;        // 完整长度
    __u16 source;           // 源节点编号
    __u16 destination;      // 目的节点编号
    struct PVFField pvf;    // PVF 字段
    struct PPFField ppf;    // PPF 字段
};

#endif //LOADABLE_KERNEL_MODULE_PATH_VALIDATION_HEADER_H
