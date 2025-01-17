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

#include "ehip_netdev.h"
#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */


#include <eh_types.h>
#include <eh_mem_pool.h>
#include <ehip-ipv4/arp.h>
#include <ehip-mac/hw_addr.h>
#include <stdint.h>

typedef struct ehip_buffer ehip_buffer_t;
struct route_info;


struct fragment_info{
    ehip_buffer_t      *fragment_buffer;
    uint16_t            fragment_start_offset;
    uint16_t            fragment_end_offset;
};

struct ip_rx_fragment{
    uint8_t                 fragment_sort[EHIP_IP_MAX_FRAGMENT_NUM];
    struct fragment_info    fragment_info[EHIP_IP_MAX_FRAGMENT_NUM];
    uint8_t                 expires_cd;
    uint8_t                 fragment_cnt;
};

struct ip_tx_fragment{
    uint16_t                fragment_offset;
    uint8_t                 fragment_read_offset;
    uint8_t                 fragment_add_offset;
    ehip_buffer_t           *fragment_buffer[EHIP_IP_MAX_FRAGMENT_NUM];
};

struct ip_message{
    struct ip_hdr                       ip_hdr;
    uint8_t                            *options_bytes;
    union{
        ehip_buffer_t                  *buffer;             /* 不分片时 */
        struct ip_rx_fragment          *rx_fragment;        /* 接收分片报文时 */
        struct ip_tx_fragment          *tx_fragment;        /* 发送分片报文时 */
        ehip_netdev_t                  *tx_init_netdev;
    };
    struct {
        struct ehip_max_hw_addr		        dts_hw_addr;
    }tx_param;

#define   IP_MESSAGE_FLAG_TX                0x00000001            // bit0: 1:发送报文 0:接收报文
#define   IP_MESSAGE_FLAG_FRAGMENT          0x00000002            // bit1: 1:分片报文 0:不分片报文
#define   IP_MESSAGE_FLAG_BROKEN            0x00000004            // bit2: 1:破碎的分片报文 0:正常分片报文
#define   IP_MESSAGE_FLAG_TX_BUFFER_INIT    0x00000008            // bit3: 1:TX_BUFFER已经初始化 0:TX_BUFFER未初始化
#define   IP_MESSAGE_FLAG_TX_READY          0x00000010            // bit4: 1:TX报文已经准备好 0:TX报文未准备好
    uint32_t                                flags;
};


#define ip_message_flag_is_tx(msg)          ((msg)->flags & IP_MESSAGE_FLAG_TX)
#define ip_message_flag_is_fragment(msg)    ((msg)->flags & IP_MESSAGE_FLAG_FRAGMENT)
#define ip_message_flag_is_broken(msg)      ((msg)->flags & IP_MESSAGE_FLAG_BROKEN)
#define ip_message_flag_is_tx_buffer_init(msg)     ((msg)->flags & IP_MESSAGE_FLAG_TX_BUFFER_INIT)
#define ip_message_flag_is_tx_ready(msg)    ((msg)->flags & IP_MESSAGE_FLAG_TX_READY)

/**
 * @brief                   创建一个可用于发送的IP报文信息
 * @param  netdev           准备发送该报文的网卡
 * @param  tos              服务类型
 * @param  ttl              生存时间
 * @param  protocol         协议类型
 * @param  src_addr         源地址
 * @param  dst_addr         目标地址
 * @param  dts_hw_addr      目标硬件地址
 * @return struct ip_message* 
 */
extern struct ip_message* ip_message_tx_new(ehip_netdev_t *netdev, uint8_t tos,
    uint8_t ttl, uint8_t protocol, ipv4_addr_t src_addr, ipv4_addr_t dst_addr, 
    struct ehip_max_hw_addr *dts_hw_addr, uint8_t *options_bytes, ehip_buffer_size_t options_bytes_size);

/**
 * @brief                   往ip tx message中添加一个buffer, 返回的buffer中会自动预留出mac和ip头部的空间
 * @param  msg_hander       返回由ip_message_tx_new创建的ip_message_t结构体
 * @param  out_buffer       返回的buffer
 * @param  out_buffer_size  返回的此buffer可填充的大小
 * @return int
 */
extern int ip_message_tx_add_buffer(struct ip_message* msg_hander, ehip_buffer_t** out_buffer, ehip_buffer_size_t *out_buffer_size);

/**
 * @brief                   完成一个ip tx message的构建,当调用该函数后，会自动填充全部的mac和ip头部
 * @param  msg_hander       返回由ip_message_tx_new创建的ip_message_t结构体
 * @return int              成功返回0，失败返回负数
 */
extern int ip_message_tx_ready(struct ip_message *msg_hander);


/**
 * @brief                   创建一个用于接收的IP消息
 * @param  netdev           接收该报文的网卡
 * @param  buffer           接收到的buffer, buffer的传入意味着所有权的转让，请勿重复unref
 * @param  ip_hdr           解析出的ip头部
 * @return struct ip_message* 
 */
extern struct ip_message* ip_message_rx_new(ehip_netdev_t *netdev, ehip_buffer_t *buffer, const struct ip_hdr *ip_hdr);

/**
 * @brief                   创建一个用于接收的IP消息,并且该报文是一个分片报文,可接收后面合并其他分片
 * @param  netdev           接收该报文的网卡
 * @param  buffer           接收到的buffer, buffer的传入意味着所有权的转让，请勿重复unref
 * @param  ip_hdr           解析出的ip头部
 * @return struct ip_message* 
 */
extern struct ip_message* ip_message_rx_new_fragment(ehip_netdev_t *netdev, ehip_buffer_t *buffer, const struct ip_hdr *ip_hdr);


/**
 * @brief                将一个新的ip msg合并到分片的 ip_message_t 结构体中
 * @param  fragment      要添加的分片片段的 ip_message_t 结构体
 * @param  buffer        要添加的分片片段的 buffer, buffer的传入意味着所有权的转让，请勿重复unref
 * @param  ip_hdr        要添加的分片片段的 ip 头部
 * @return int           成功返回0，重组完成返回 FRAGMENT_REASSE_FINISH, 失败返回负数
 */
#define FRAGMENT_REASSE_FINISH  1
extern int ip_message_rx_merge_fragment(struct ip_message *fragment, ehip_buffer_t *buffer, const struct ip_hdr *ip_hdr);


/**
 * @brief      遍历一个分片片段的 ip_message_t 结构体
 * @param  pos_buffer       分片片段的 ehip_buffer_t 结构体指针
 * @param  int_tmp_i        分片片段的索引,临时使用
 * @param  int_tmp_sort_i   分片片段的排序索引，临时使用
 * @param  ip_fragment_msg  要遍历的 ip_message_t 结构体
 */
#define ip_message_rx_fragment_for_each(pos_buffer, int_tmp_i, int_tmp_sort_i,  ip_fragment_msg) \
    for( int_tmp_i = 0, int_tmp_sort_i = ip_fragment_msg->rx_fragment->fragment_sort[int_tmp_i]; \
        int_tmp_i < ip_fragment_msg->rx_fragment->fragment_cnt && int_tmp_sort_i < (int)EHIP_IP_MAX_FRAGMENT_NUM && \
        ((pos_buffer = ip_fragment_msg->rx_fragment->fragment_info[int_tmp_sort_i].fragment_buffer) || 1U); \
        int_tmp_sort_i = ip_fragment_msg->rx_fragment->fragment_sort[++int_tmp_i])


/**
 * @brief      遍历一个分片片段的 ip_message_t 结构体
 * @param  pos_buffer       分片片段的 ehip_buffer_t 结构体指针
 * @param  int_tmp_i        分片片段的索引
 * @param  ip_fragment_msg  要遍历的 ip_message_t 结构体
 */
#define ip_message_tx_fragment_for_each(pos_buffer, int_tmp_i, ip_fragment_msg) \
    for( int_tmp_i = ip_fragment_msg->tx_fragment->fragment_read_offset; \
         int_tmp_i < ip_fragment_msg->tx_fragment->fragment_add_offset && \
         ((pos_buffer = ip_fragment_msg->tx_fragment->fragment_buffer[int_tmp_i]) || 1U); \
         int_tmp_i++)


/**
 * @brief     释放一个 ip_message_t 结构体,若内部拥有ehip_buffer_t 则一同解除引用
 * @param  msg                 要释放的 ip_message_t 结构体
 */
extern void ip_message_free(struct ip_message *msg);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _IP_MESSAGE_H_