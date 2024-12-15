/**
 * @file arp.h
 * @brief arp protocol
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-11-13
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */

#ifndef __IPV4_ARP_H__
#define __IPV4_ARP_H__


#ifndef _ARP_H_
#define _ARP_H_

#include <stdint.h>
#include <eh_types.h>
#include <eh_signal.h>
#include <ehip_netdev.h>
#include <ehip-mac/hw_addr.h>
#include <ehip-ipv4/ip.h>
#include <ehip_netdev_trait.h>
#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

struct arp_hdr{
	uint16_t		ar_hrd;		/* format of hardware address	*/
	uint16_t		ar_pro;		/* format of protocol address	*/
    uint8_t	        ar_hln;		/* length of hardware address	*/
	uint8_t	        ar_pln;		/* length of protocol address	*/
	uint16_t		ar_op;		/* ARP opcode (command)		*/
}eh_aligned(sizeof(char));

/**
 * @brief arp表条目变化信号，当有邻近项有效或者无效状态发生变化时会触发该信号
 */
EH_EXTERN_SIGNAL(signal_arptable_changed);

struct arp_entry{
	union{
		uint16_t 					reachable_time_cd;
		uint16_t					stale_time;
	};
	union{
		uint16_t 					delay_probe_time_cd;
		uint16_t					retry_cnt;
	};
	struct ehip_netdev			*netdev;
	ipv4_addr_t					ip_addr;
	struct ehip_max_hw_addr		hw_addr;
	uint8_t						state;
};


/* ARP protocol opcodes. */
#define	ARPOP_REQUEST	1		/* ARP request			*/
#define	ARPOP_REPLY		2		/* ARP reply			*/
#define	ARPOP_RREQUEST	3		/* RARP request			*/
#define	ARPOP_RREPLY	4		/* RARP reply			*/
#define	ARPOP_InREQUEST	8		/* InARP request		*/
#define	ARPOP_InREPLY	9		/* InARP reply			*/
#define	ARPOP_NAK		10		/* (ATM)ARP NAK			*/


static inline unsigned int arp_hdr_len(const ehip_netdev_t *dev)
{
	return sizeof(struct arp_hdr) + ((size_t)dev->attr.hw_addr_len + sizeof(uint32_t)) * 2;
}

/**
 * @brief                   查询ip地址对应的arp表项，若表项不存在，需要等signal_arptable_changed信号触发后，
 *                          再进行查询
 * @param  netdev           网卡设备句柄指针，也作为参数，用于判断arp表项是否属于该网卡
 * @param  ip_addr          ip地址
 * @param  odl_idx_or_minus arp表旧的索引，若该条目还存在，则可以加快查询，
 *                          若为负数则轮询整个arp表。
 * @return int              成功返回0及正数(idx)，失败返回负数，若需要进行慢查询，则返回EH_RET_AGAIN
 *                          上层协议需要等signal_arptable_changed信号触发后，再进行查询
 */
extern int arp_query(const ehip_netdev_t *netdev, const ipv4_addr_t ip_addr, int odl_idx_or_minus);

/**
 * @brief                   如果三层或者以上的协议确认了该IP的可达性，则调用该函数告诉arp层
 * @param  netdev           网卡设备句柄指针，也作为参数，用于判断arp表项是否属于该网卡
 * @param  ip_addr          ip地址
 * @param  odl_idx_or_minus arp表旧的索引，若该条目还存在，则可以加快函数过程
 * @return int 
 */
extern int arp_update_reachability(const ehip_netdev_t *netdev, const ipv4_addr_t ip_addr, int odl_idx_or_minus);


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _ARP_H_



#endif