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

#include <ehip-ipv4/ip.h>
#include <ehip-ipv4/ip_message.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

struct icmp_hdr {
  uint8_t		type;
  uint8_t		code;
  uint16_t	    checksum;
  union {
	struct {
		/* 
		 * 在windows中一般是进程id，我们只需要在ping时需要保持过程中的唯一性，
		 * 若是被ping，则需要在回显报文中复制该值
		 * sequence值，用于标识报文序号，在回显时需要复制该值 
		 */
		uint16_be_t	id;	
		uint16_be_t	sequence;
	}echo;
	struct {
		uint16_be_t	__unused;
		uint16_be_t	mtu;
	}frag;
	ipv4_addr_t	gateway;
	uint8_t	reserved[4];
  };
};

extern int icmp_fill(struct ip_message *ip_msg);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _ICMP_H_