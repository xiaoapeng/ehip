/**
 * @file ip_raw_error.h
 * @brief 原始错误处理
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-05-09
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */
#ifndef _RAW_ERROR_H_
#define _RAW_ERROR_H_

#include <ehip-ipv4/ip.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

extern void ip_raw_error(ipv4_addr_t err_sender, struct ip_hdr *ip_hdr, const uint8_t *payload, int payload_len, int error);


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _RAW_ERROR_H_