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
#include <eh_llist.h>
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
	uint16_be_t		ar_hrd;		/* format of hardware address	*/
	uint16_be_t		ar_pro;		/* format of protocol address	*/
    uint8_t	        ar_hln;		/* length of hardware address	*/
	uint8_t	        ar_pln;		/* length of protocol address	*/
	uint16_be_t		ar_op;		/* ARP opcode (command)		*/
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
	struct eh_llist_head		callback_list;
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

/* 当ipdev不支持ARP时，可使用该项，该项将使用 默认 0xFF*N 的mac地址 */
#define ARP_MARS_IDX	EHIP_ARP_CACHE_MAX_NUM 

/* arp表， 禁止直接访问 */
extern struct arp_entry _arp_table[];

/**
 * @brief arp表条目变化信号，当有邻近项有效或者无效状态发生变化时会触发该信号
 */
EH_EXTERN_SIGNAL(signal_arp_table_changed);

static inline unsigned int arp_hdr_len(const ehip_netdev_t *dev)
{
	return sizeof(struct arp_hdr) + ((size_t)dev->attr.hw_addr_len + sizeof(uint32_t)) * 2;
}

/**
 * @brief                   查询ip地址对应的arp表项
 *                          再进行查询
 * @param  netdev           网卡设备句柄指针，也作为参数，用于判断arp表项是否属于该网卡
 * @param  ip_addr          ip地址
 * @param  old_idx_or_minus 输入旧的索引值，旧的索引值可加快查询速度，当为负数时，遍历整个ARP表
 * @return int              成功返回索引值，失败返回负数。
 */
extern int arp_query(const ehip_netdev_t *netdev, const ipv4_addr_t ip_addr, int old_idx_or_minus);

enum change_callback_return{
	ARP_CALLBACK_CONTINUE = 0,
	ARP_CALLBACK_ABORT = 1
};

struct arp_changed_callback{
	struct eh_llist_node		node;
	int 						idx;
	enum change_callback_return (*callback)(struct arp_changed_callback *callback_action);
};

/**
 * @brief 							arp表项变化回调函数注册
 * @param  callback_action         回调动作结构块
 * @return int 						成功返回0，失败返回负数
 */
extern int arp_changed_callback_register(struct arp_changed_callback *callback_action);

/**
 * @brief 							arp表项变化回调函数注销
 * @param  callback_action         回调动作结构块
 */
extern int arp_changed_callback_unregister(struct arp_changed_callback *callback_action);

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
#define arp_get_table_entry(idx) (_arp_table + (idx))

/**
 * @brief 					判断邻居项是否有效
 * @param  idx 				邻居项索引
 * @return bool 			有效返回true，无效返回false
 */
#define arp_entry_neigh_is_valid(idx) (arp_get_table_entry(idx)->state >= ARP_STATE_NUD_STALE) 


/**
 * @brief 					arp表打印 
 */
extern void arp_table_dump(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _ARP_H_



#endif