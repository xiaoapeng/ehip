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

#include <stdbool.h>
#include <stdint.h>

#include <eh_types.h>
#include <eh_mem_pool.h>
#include <ehip_buffer.h>
#include <ehip_netdev.h>
#include <ehip-mac/hw_addr.h>
#include <ehip-ipv4/arp.h>
#include <ehip-ipv4/route.h>


#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

struct ip_message{
    struct ip_hdr                       ip_hdr;
    uint8_t                            *options_bytes;
    struct eh_llist_head                buffer_head;      /* 进行分片时，用于存储分片 */
    ehip_netdev_t                       *netdev;

#define   IP_MESSAGE_FLAG_TX                0x01            // bit0: 1:发送报文 0:接收报文
#define   IP_MESSAGE_FLAG_BROKEN            0x02            // bit2: 1:破碎的分片报文 0:正常分片报文
#define   IP_MESSAGE_FLAG_READY             0x04            // bit3: 1:TX报文已经准备好 0:TX报文未准备好
#define   IP_MESSAGE_FLAG_FRAGMENT          0x08            // bit1: 1:分片报文 0:不分片报文

    uint8_t                             flags;
    union{
        uint8_t                             tx_header_size;
        uint8_t                             rx_fragment_cnt;
    };
    uint8_t                             rx_fragment_expires_cd; // RX分片超时时间
    uint8_t                             route_type;         // 路由类型 enum route_table_type
};


#define ip_message_flag_is_tx(msg)          ((msg)->flags & IP_MESSAGE_FLAG_TX)
#define ip_message_flag_is_rx(msg)          (!((msg)->flags & IP_MESSAGE_FLAG_TX))
#define ip_message_flag_is_broken(msg)      ((msg)->flags & IP_MESSAGE_FLAG_BROKEN)
#define ip_message_flag_is_fragment(msg)    ((msg)->flags & IP_MESSAGE_FLAG_FRAGMENT)
#define ip_message_flag_is_ready(msg)       ((msg)->flags & IP_MESSAGE_FLAG_READY)


/**
 * @brief                        创建一个可用于发送的IP报文信息
 * @param  netdev                准备发送该报文的网卡
 * @param  tos                   服务类型
 * @param  ttl                   生存时间
 * @param  protocol              协议类型
 * @param  src_addr              源地址
 * @param  dst_addr              目标地址
 * @param  options_bytes         选项数据
 * @param  options_bytes_size    选项数据的长度
 * @param  header_reserved_size  预留的头部空间大小,此空间一般用于UDP/TCP等协议的头部
 * @param  route_type            路由类型
 * @return struct ip_message*    应该使用 eh_ptr_to_error 来判断错误码，若成功应该为0，失败为负数
 */
extern struct ip_message* ip_message_tx_new(ehip_netdev_t *netdev, uint8_t tos,
    uint8_t ttl, uint8_t protocol, ipv4_addr_t src_addr, ipv4_addr_t dst_addr, 
     uint8_t *options_bytes, ehip_buffer_size_t options_bytes_size, uint8_t header_reserved_size, 
     enum route_table_type route_type);

/**
 * @brief                   往ip tx message中添加一个buffer
 * @param  msg_hander       返回由ip_message_tx_new创建的ip_message_t结构体
 * @param  out_buffer       返回的buffer
 * @return int
 */
extern int ip_message_tx_add_buffer(struct ip_message* msg_hander, ehip_buffer_t** out_buffer);

/**
 * @brief                   完成一个ip tx message的打包,当调用该函数后，
 *                          会自动填充全部ip头部,若tx_header_size大于0且head_data不为NULL，则会填充应用头部
 * @param  msg_hander       返回由ip_message_tx_new创建的ip_message_t结构体
 * @param  head_data        应用层头部数据
 * @return int              成功返回0，失败返回负数
 */
extern int ip_message_tx_ready(struct ip_message *msg_hander, const uint8_t *head_data);


/**
 * @brief                   创建一个用于接收的IP消息
 * @param  netdev           接收该报文的网卡
 * @param  buffer           接收到的buffer, buffer的传入意味着所有权的转让，请勿重复unref
 * @param  ip_hdr           解析出的ip头部
 * @param  route_type            路由类型
 * @return struct ip_message*    应该使用 eh_ptr_to_error 来判断错误码，若成功应该为0，失败为负数
 */
extern struct ip_message* ip_message_rx_new(ehip_netdev_t *netdev, ehip_buffer_t *buffer, const struct ip_hdr *ip_hdr, enum route_table_type route_type);

/**
 * @brief                   创建一个用于接收的IP消息,并且该报文是一个分片报文,可接收后面合并其他分片
 * @param  netdev           接收该报文的网卡
 * @param  ip_hdr           解析出的ip头部
 * @param  route_type            路由类型
 * @return struct ip_message*    应该使用 eh_ptr_to_error 来判断错误码，若成功应该为0，失败为负数
 */
extern struct ip_message* ip_message_rx_new_fragment(ehip_netdev_t *netdev, const struct ip_hdr *ip_hdr, enum route_table_type route_type);


/**
 * @brief                将一个新的ip msg添加到到分片的 ip_message_t 结构体中
 * @param  fragment      要添加的分片片段的 ip_message_t 结构体
 * @param  buffer        要添加的分片片段的 buffer, buffer的传入意味着所有权的转让，请勿重复unref
 * @param  ip_hdr        要添加的分片片段的 ip 头部
 * @return int           成功返回0，重组完成返回 FRAGMENT_REASSEMBLY_FINISH, 失败返回负数
 */
#define FRAGMENT_REASSEMBLY_FINISH  1
extern int ip_message_rx_add_fragment(struct ip_message *fragment, ehip_buffer_t *buffer, const struct ip_hdr *ip_hdr);


/**
 * @brief      遍历一个分片片段的 ip_message_t 结构体
 * @param  buffer_pos       分片片段的 ehip_buffer_t 结构体指针
 * @param  ip_fragment_msg  要遍历的 ip_message_t 结构体
 */
#define ip_message_fragment_for_each(buffer_pos, ip_fragment_msg)                                       \
    for ((buffer_pos) = ({                                                                              \
                      eh_static_assert(                                                                 \
                          eh_same_type(ip_fragment_msg, struct ip_message *),                           \
                          "pointer type mismatch in struct ip_message"                                  \
                      );                                                                                \
                      eh_llist_entry(                                                                   \
                            (ip_fragment_msg)->buffer_head.first,                                       \
                            typeof(*(buffer_pos)), node);                                               \
                  });                                                                                   \
	     eh_member_address_is_nonnull(buffer_pos, node) && ehip_buffer_get_payload_size(buffer_pos);    \
	     (buffer_pos) = eh_llist_entry((buffer_pos)->node.next, typeof(*(buffer_pos)), node))

/**
 * @brief      获取普通ip message第一个buffer
 */
#define ip_message_buffer(ip_msg) eh_llist_entry_safe(eh_llist_first(&(ip_msg)->buffer_head), ehip_buffer_t, node)


/**
 * @brief       获取ip message的route_type
 */
#define ip_message_route_type(ip_msg) ((enum route_table_type)((ip_msg)->route_type))

/**
 * @brief     释放一个 ip_message_t 结构体,若内部拥有ehip_buffer_t 则一同解除引用
 * @param  msg                 要释放的 ip_message_t 结构体
 */
extern void ip_message_free(struct ip_message *msg);



enum _ip_message_read_advanced_type{
    IP_MESSAGE_READ_ADVANCED_REAL_COPY_READ,
    /* 自动区分0拷贝和非0拷贝 */
    IP_MESSAGE_READ_ADVANCED_TYPE_SMART_READ,
    IP_MESSAGE_READ_ADVANCED_ZERO_COPY_READ,
    IP_MESSAGE_READ_ADVANCED_MAX
};

extern int _ip_message_rx_read_advanced(struct ip_message *msg_hander, uint8_t **out_data, 
    ehip_buffer_size_t size, uint8_t *out_standby_buffer, enum _ip_message_read_advanced_type type);

/**
 * @brief                       读取一个ip_message_t中的数据,当读取大小小于第一块分片的大小,则直接返回内部指针
 * @param  msg                  msg description
 * @param  out_data             输出
 * @param  size                 要读的数据大小
 * @param  out_standby_buffer   当读取大小大于第一块分片的大小,则需要拼接在out_standby_buffer中，用户需要提供大于等于size的缓冲区
 * @return int              失败返回负数，成功返回读取的数据大小
 */
static inline int ip_message_rx_smart_read(struct ip_message *msg, uint8_t **out_data, 
    ehip_buffer_size_t size, uint8_t *out_standby_buffer){
    return _ip_message_rx_read_advanced(msg, out_data, size, 
        out_standby_buffer, IP_MESSAGE_READ_ADVANCED_TYPE_SMART_READ);
}

/**
 * @brief                   读取一个ip_message_t中的数据,并直接覆盖到out_data中
 * @param  msg              msg description
 * @param  data         输出的缓冲区
 * @param  size             缓冲区大小
 * @return int              失败返回负数，成功返回读取的数据大小
 */
static inline int ip_message_rx_real_read(struct ip_message *msg, uint8_t *data, ehip_buffer_size_t size){
    uint8_t *_out_data = NULL;
    return _ip_message_rx_read_advanced(msg, &_out_data, size, 
        data, IP_MESSAGE_READ_ADVANCED_REAL_COPY_READ);
}

/**
 * @brief                   假装读取一个ip_message_t中的数据,读指针偏移
 * @param  msg              msg description
 * @param  size             要读的数据大小
 * @return int              失败返回负数，成功返回读取的数据大小
 */
extern int ip_message_rx_read_skip(struct ip_message *msg, ehip_buffer_size_t size);


/**
 * @brief                   获取一个ip_message_t中的数据大小
 * @param  msg              msg description
 * @return int              失败返回负数，成功返回读取的数据大小
 */
extern int  ip_message_rx_data_size(struct ip_message *msg);


/**
 * @brief                   减少一个ip_message_t尾部的数据大小，在传递给用户时有用（修剪一些尾部的多余数据）
 * @param  msg              My Param doc
 * @param  size             My Param doc
 * @return int 
 */
extern int ip_message_rx_data_tail_trim(struct ip_message *msg, ehip_buffer_size_t size);

/**
 * @brief                   获取ip_message中的网卡设备
 * @param  msg              msg description
 * @return ehip_netdev_t
 */
static inline ehip_netdev_t *ip_message_get_netdev(struct ip_message *msg){
    if(msg == NULL) return NULL;
    return msg->netdev;
}

/**
 * @brief                   引用一个rx ip_message_t中的数据到一个新的rx ip_message_t中，buffer内部引用计数++
 * @param  msg              msg description
 * @return ehip_netdev_t    应该使用 eh_ptr_to_error 来判断错误码，若成功应该为0，失败为负数
 */
extern struct ip_message *ip_message_rx_ref_dup(struct ip_message *msg);


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _IP_MESSAGE_H_