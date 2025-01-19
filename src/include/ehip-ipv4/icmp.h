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

extern int icmp_input(struct ip_message *ip_msg);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _ICMP_H_