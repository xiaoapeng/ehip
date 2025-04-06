/**
 * @file udp.h
 * @brief 
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-03-09
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */

#ifndef _UDP_H_
#define _UDP_H_

#include <eh.h>
#include <eh_swab.h>
#include <ehip-ipv4/ip.h>
#include <ehip-ipv4/ip_message.h>
#include <ehip-ipv4/route.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

#define UDP_PCB_FLAGS_NOCHKSUM       0x01U
#define UDP_PCB_FLAGS_UDPLITE        0x02U

struct __packed udp_hdr {
    uint16_be_t         source;
    uint16_be_t         dest;
    uint16_be_t         len;
    uint16_t            check;
};


typedef int* udp_pcb_t;


struct udp_sender {
    struct ip_message   *ip_msg;
    eh_clock_t          last_check_time;
    udp_pcb_t           pcb;

    enum route_table_type route_type;
    ehip_netdev_t       *netdev;

    ipv4_addr_t         src_addr;
    ipv4_addr_t         dts_addr;
    uint16_be_t         dts_port;
    uint16_be_t         src_port;

    union {
        struct{
            ipv4_addr_t         gw_addr;
            int                 arp_idx_cache;
        };
        /* 环回模式下以网卡指针值作为物理地址，方便环回rx处理时处理数据包 */
        ehip_netdev_t           *loopback_virtual_hw_addr;
    };

};

/* DHCP 客户端所绑定地址 */
#define IPV4_ADDR_DHCP_CLIENT             ipv4_make_addr(0,0,0,0)

/**
 * @brief                   创建一个udp上下文句柄,该方法会限定接口和ip地址
 * @param  bind_addr        限定的IP地址
 * @param  bind_port        收发使用的端口号
 * @param  netdev           限定的网络设备
 * @return udp_pcb_t        返回值需要使用 eh_ptr_to_error 进行错误码判断
 */
extern udp_pcb_t ehip_udp_new(ipv4_addr_t bind_addr, uint16_be_t bind_port , ehip_netdev_t *netdev);

/**
 * @brief                   创建一个udp上下文句柄,该方法会接收现有的所有接口的报文
 * @param  bind_port        收发使用的端口号
 * @return udp_pcb_t        返回值需要使用 eh_ptr_to_error 进行错误码判断
 */
extern udp_pcb_t ehip_udp_any_new(uint16_be_t bind_port);

/**
 * @brief                   删除一个udp上下文句柄
 * @param  pcb              ehip_udp_new or ehip_udp_any_new 接口返回的udp上下文句柄
 */
extern void      ehip_udp_delete(udp_pcb_t pcb);

/**
 * @brief                   设置udp上下文句柄的标志位
 * @param  pcb              ehip_udp_new or ehip_udp_any_new 接口返回的udp上下文句柄
 * @param  flags            标志位
 */
extern void      ehip_udp_set_flags(udp_pcb_t pcb, uint32_t flags);

/**
 * @brief                   设置udp上下文句柄的用户数据,这在回调中进行个性化处理时非常有用
 * @param  pcb              ehip_udp_new or ehip_udp_any_new 接口返回的udp上下文句柄
 * @param  userdata         用户数据
 */
extern void      ehip_udp_set_userdata(udp_pcb_t pcb, void *userdata);

/**
 * @brief                   获取udp上下文句柄的用户数据
 * @param  pcb              ehip_udp_new or ehip_udp_any_new 接口返回的udp上下文句柄
 * @return void* 
 */
extern void*     ehip_udp_get_userdata(udp_pcb_t pcb);

/**
 * @brief                   设置udp上下文句柄的接收回调函数
 * @param  pcb              ehip_udp_new or ehip_udp_any_new 接口返回的udp上下文句柄
 * @param  recv_callback    接收回调函数
 */
extern void      ehip_udp_set_recv_callback(udp_pcb_t pcb, 
    void (*recv_callback)(udp_pcb_t pcb, ipv4_addr_t addr, uint16_be_t port, struct ip_message *udp_rx_meg));

/**
 * @brief                   设置udp上下文句柄的错误回调函数
 * @param  pcb              ehip_udp_new or ehip_udp_any_new 接口返回的udp上下文句柄
 * @param  error_callback   错误回调函数
 */
extern void ehip_udp_set_error_callback(udp_pcb_t pcb, 
    void (*error_callback)(udp_pcb_t pcb, ipv4_addr_t addr, uint16_be_t port, int err));

/**
 * @brief                   初始化udp报文发送器,在初始化成功后可反复使用，
 *                           复用前请使用ehip_udp_sender_buffer_clean进行清理，
 *                           然后重新ehip_udp_sender_add_buffer
 * @param  pcb              ehip_udp_new or ehip_udp_any_new 接口返回的udp上下文句柄
 * @param  sender           udp报文发送器
 * @param  dts_addr         目标地址
 * @param  dts_port         目标端口
 * @return int 
 */
extern int       ehip_udp_sender_init_ready(udp_pcb_t pcb, struct udp_sender *sender, 
        ipv4_addr_t dts_addr, uint16_be_t dts_port);

/**
 * @brief                   判断udp报文发送器是否初始化
 * @param  sender           udp报文发送器
 * @return bool
 */
#define          ehip_udp_sender_is_init(sender)  ((sender)->netdev != NULL)
/**
 * @brief                   清理udp报文发送器
 * @param  sender           udp报文发送器
 */
extern void      ehip_udp_sender_buffer_clean(struct udp_sender *sender);

/**
 * @brief                                添加udp报文发送缓冲区
 * @param  sender                        udp报文发送器
 * @param  out_buffer                    输出缓冲区
 * @param  out_buffer_capacity_size      可用缓冲区大小
 * @return int 
 */
extern int       ehip_udp_sender_add_buffer(struct udp_sender *sender, 
        ehip_buffer_t** out_buffer, ehip_buffer_size_t *out_buffer_capacity_size);


/**
 * @brief                   发送udp报文
 * @param  pcb              ehip_udp_new or ehip_udp_any_new 接口返回的udp上下文句柄
 * @param  sender           udp报文发送器
 * @return int 
 */
extern int       ehip_udp_send(udp_pcb_t pcb, struct udp_sender *sender);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _UDP_H_