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


enum etharp_state{
    ARP_STATE_NUD_FAILED,                   /* 未使用状态，该状态邻居项无效 */
    ARP_STATE_NUD_NONE,                     /* 刚建立状态，该状态邻居项无效 */
    ARP_STATE_NUD_INCOMPLETE,               /* 定时发送Solicitation请求，该状态邻居项无效 */
    ARP_STATE_NUD_STALE,                    /* 不新鲜了，随时会被垃圾回收,但若被使用，则会迁移到ARP_STATE_NUD_DELAY，该状态邻居项有效 */
    ARP_STATE_NUD_PROBE,                    /* delay_probe_time超时后，定时发送Solicitation请求，该状态邻居项有效 */
    ARP_STATE_NUD_DELAY,                    /* reachable_time超时但delay_probe_time未超时，当delay_probe_time超时时迁移到ARP_STATE_NUD_PROBE */
    ARP_STATE_NUD_REACHABLE                 /* 绝对可信状态，reachable_time超时后迁移出此状态 */
};

/* ARP protocol opcodes. */
#define	ARPOP_REQUEST	1		/* ARP request			*/
#define	ARPOP_REPLY		2		/* ARP reply			*/
#define	ARPOP_RREQUEST	3		/* RARP request			*/
#define	ARPOP_RREPLY	4		/* RARP reply			*/
#define	ARPOP_InREQUEST	8		/* InARP request		*/
#define	ARPOP_InREPLY	9		/* InARP reply			*/
#define	ARPOP_NAK		10		/* (ATM)ARP NAK			*/


/**
 * @brief arp表条目变化信号，当有邻近项有效或者无效状态发生变化时会触发该信号
 */
EH_EXTERN_SIGNAL(signal_arp_table_changed);

static inline unsigned int arp_hdr_len(const ehip_netdev_t *dev)
{
	return sizeof(struct arp_hdr) + ((size_t)dev->attr.hw_addr_len + sizeof(uint32_t)) * 2;
}

/**
 * @brief                   查询ip地址对应的arp表项，若表项不存在，需要等signal_arptable_changed信号触发后，
 *                          再进行查询
 * @param  netdev           网卡设备句柄指针，也作为参数，用于判断arp表项是否属于该网卡
 * @param  ip_addr          ip地址
 * @param  odl_idx_or_minus_or_out_idx 
							int odl_idx_or_minus_or_out_idx = old;
							arp_query(...., &odl_idx_or_minus_or_out_idx);
							作为输入参数时：
								输入旧的索引值，当旧的索引值为负数时，将遍历整个arp表,
							作为输出参数时：
								当返回值为不是EH_RET_AGAIN负数时,*odl_idx_or_minus_or_out_idx 为 -1
								当返回值为0时，*odl_idx_or_minus_or_out_idx 为 arp 表项的索引值
								当返回值为EH_RET_AGAIN时，*odl_idx_or_minus_or_out_idx 为 表项的索引值
 * @return int              返回0成功，*odl_idx_or_minus_or_out_idx 为 arp 表项的索引值
 *							返回EH_RET_AGAIN意味着要进行慢查询，*odl_idx_or_minus_or_out_idx 为 arp 表项的索引值
 *							返回负数失败。
 *                          上层协议需要等signal_arptable_changed信号触发后，再进行查询
 */
extern int arp_query(const ehip_netdev_t *netdev, const ipv4_addr_t ip_addr, int *old_idx_or_minus_or_out_idx);

/**
 * @brief                   如果三层或者以上的协议确认了该IP的可达性，则调用该函数告诉arp层
 * @param  netdev           网卡设备句柄指针，也作为参数，用于判断arp表项是否属于该网卡
 * @param  ip_addr          ip地址
 * @param  old_idx_or_minus arp表旧的索引，若该条目还存在，则可以加快函数过程
 * @return int 
 */
extern int arp_update_reachability(const ehip_netdev_t *netdev, const ipv4_addr_t ip_addr, int old_idx_or_minus);

/**
 * @brief 					获取arp表
 * @return const struct arp_entry* 
 */
extern const struct arp_entry* arp_get_table_entry(int idx);


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _ARP_H_



#endif