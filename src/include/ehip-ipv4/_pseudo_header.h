/**
 * @file _pseudo_header.h
 * @brief tcp/udp 伪头部
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-03-28
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */
#ifndef __PSEUDO_HEADER_H_
#define __PSEUDO_HEADER_H_

#include <ehip-ipv4/ip.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

// 用户态伪头部示例（IPv4 TCP）
struct pseudo_header {
    ipv4_addr_t         src_addr;
    ipv4_addr_t         dst_addr;
    uint8_t             zero;
    uint8_t             proto;
    uint16_be_t         len;
}__packed;




#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // __PSEUDO_HEADER_H_