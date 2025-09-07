/**
 * @file icmp.h
 * @brief 
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-12-31
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */

#ifndef _ICMP_H_
#define _ICMP_H_

#include <eh_types.h>
#include <ehip-ipv4/ip.h>
#include <ehip-ipv4/ip_message.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

struct __packed icmp_hdr {
    uint8_t        type;
    uint8_t        code;
    uint16_t        checksum;
    union {
        struct {
            /* 
            * 在windows中一般是进程id，我们只需要在ping时需要保持过程中的唯一性，
            * 若是被ping，则需要在回显报文中复制该值
            * sequence值，用于标识报文序号，在回显时需要复制该值 
            */
            uint16_be_t    id;
            uint16_be_t    sequence;
        }echo;
        struct {
            uint16_be_t    unused;
            uint16_be_t    mtu;
        }frag;
        ipv4_addr_t    gateway;
        uint8_t    reserved[4];
    };
};

#define ICMP_TYPE_ECHO_REPLY            0       /* 回显应答                      */
#define ICMP_TYPE_DEST_UNREACH          3       /* Destination Unreachable      */
#define ICMP_TYPE_SOURCE_QUENCH         4       /* Source Quench                */
#define ICMP_TYPE_REDIRECT              5       /* Redirect (change route)      */
#define ICMP_TYPE_ECHO                  8       /* 回显请求                      */
#define ICMP_TYPE_TIME_EXCEEDED         11      /* Time Exceeded                */
#define ICMP_TYPE_PARAMETERPROB         12      /* Parameter Problem            */
#define ICMP_TYPE_TIMESTAMP             13      /* Timestamp Request            */
#define ICMP_TYPE_TIMESTAMPREPLY        14      /* Timestamp Reply              */
#define ICMP_TYPE_INFO_REQUEST          15      /* Information Request          */
#define ICMP_TYPE_INFO_REPLY            16      /* Information Reply            */
#define ICMP_TYPE_ADDRESS               17      /* Address Mask Request         */
#define ICMP_TYPE_ADDRESSREPLY          18      /* Address Mask Reply           */
#define NR_ICMP_TYPES                   18

#define ICMP_CODE_NET_UNREACH	            0   /* 网络不可达                    */
#define ICMP_CODE_HOST_UNREACH	            1   /* 主机不可达                    */
#define ICMP_CODE_PROT_UNREACH	            2   /* 协议不可达                    */
#define ICMP_CODE_PORT_UNREACH	            3   /* 端口不可达                    */
#define ICMP_CODE_FRAG_NEEDED	            4   /* 段太长，需要分片              */
#define ICMP_CODE_SR_FAILED		            5   /* 源路由失败                    */
#define ICMP_CODE_NET_UNKNOWN	            6   /* 未知网络                      */
#define ICMP_CODE_HOST_UNKNOWN	            7   /* 未知主机                      */
#define ICMP_CODE_HOST_ISOLATED	            8   /* 主机孤立                      */
#define ICMP_CODE_NET_ANO		            9   /* 网络被禁止                    */
#define ICMP_CODE_HOST_ANO		            10  /* 未知主机                      */
#define ICMP_CODE_NET_UNR_TOS	            11  /* 网络不可达，TOS               */
#define ICMP_CODE_HOST_UNR_TOS	            12  /* 未知主机，TOS                 */
#define ICMP_CODE_PKT_FILTERED	            13  /* 数据被过滤                    */
#define ICMP_CODE_PREC_VIOLATION	        14  /* 主机越权                      */
#define ICMP_CODE_PREC_CUTOFF	            15  /* 预处理被截断                   */

extern int icmp_fill(struct ip_message *ip_msg);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _ICMP_H_