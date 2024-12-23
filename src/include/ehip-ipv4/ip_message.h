/**
 * @file ip_message.h
 * @brief 
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-12-21
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */

#ifndef _IP_MESSAGE_H_
#define _IP_MESSAGE_H_

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */


#include "eh_types.h"
#include <eh_mem_pool.h>

#include <ehip-ipv4/ip.h>
#include <stdint.h>

typedef struct ehip_buffer ehip_buffer_t;

enum ip_message_type{
    IP_MESSAGE_TYPE_NORMAL,
    IP_MESSAGE_TYPE_FRAGMENT,
};

struct ip_fragment{
    struct ip_hdr    ip_hdr;
    ehip_buffer_t    *fragment[EHIP_IP_MAX_FRAGMENT_NUM];
};

eh_static_assert(eh_offsetof(struct ip_fragment, ip_hdr) == 0, "ip_hdr must be the first member of ip_fragment");

struct ip_message{
    union{
        struct ip_hdr               *ip_hdr;
        struct ip_fragment          *fragment;
    };
    ipv4_addr_t                 src_ip;
    ipv4_addr_t                 dst_ip;
    union{
        ehip_buffer_t               *buffer;
        ehip_buffer_t               **fragment_buffer;
    };
    uint8_t                     fragment_num;
    uint8_t                     expires_cd;
    uint8_t                     type;
};

extern struct ip_message *ip_message_new(enum ip_message_type type);
extern void ip_message_and_buffer_free(struct ip_message *msg);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _IP_MESSAGE_H_