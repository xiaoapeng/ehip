/**
 * @file tcp.h
 * @brief 
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-04-26
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */

#ifndef _TCP_H_
#define _TCP_H_

#include "ehip_buffer.h"
#include <stdint.h>
#include <eh_swab.h>
#include <eh_ringbuf.h>
#include <ehip-ipv4/ip.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

enum tcp_event{
    TCP_CONNECT_TIMEOUT = 0,
    TCP_ERROR,
    TCP_RECV_FIN,
    TCP_RECV_RST,
    TCP_SEND_TIMEOUT,
    TCP_DISCONNECTED,
    TCP_CONNECTED,
    TCP_RECV_DATA,
    TCP_RECV_ACK,
};

struct __packed tcp_hdr{
    uint16_be_t     source;
    uint16_be_t     dest;
    uint32_be_t     seq;
    uint32_be_t     ack_seq;
    union{
        struct{
#ifdef __BYTE_ORDER_LITTLE_ENDIAN__

#define TCP_FLAG_CWR 0x8000
#define TCP_FLAG_ECE 0x4000
#define TCP_FLAG_URG 0x2000
#define TCP_FLAG_ACK 0x1000
#define TCP_FLAG_PSH 0x0800
#define TCP_FLAG_RST 0x0400
#define TCP_FLAG_SYN 0x0200
#define TCP_FLAG_FIN 0x0100

            uint16_t res1:4,
                     doff:4,
                     fin:1,
                     syn:1,
                     rst:1,
                     psh:1,
                     ack:1,
                     urg:1,
                     ece:1,
                     cwr:1;
#else

#define TCP_FLAG_CWR 0x0080
#define TCP_FLAG_ECE 0x0040
#define TCP_FLAG_URG 0x0020
#define TCP_FLAG_ACK 0x0010
#define TCP_FLAG_PSH 0x0008
#define TCP_FLAG_RST 0x0004
#define TCP_FLAG_SYN 0x0002
#define TCP_FLAG_FIN 0x0001

            uint16_t doff:4,
                     res1:4,
                     cwr:1,
                     ece:1,
                     urg:1,
                     ack:1,
                     psh:1,
                     rst:1,
                     syn:1,
                     fin:1;
#endif
        };

        uint16_t        flags;              
    };
    uint16_be_t     window;
    uint16_t        check;
    uint16_t        urg_ptr;
    uint8_t         options[0];
};

#define tcp_hdr_size(hdr)             ((hdr)->doff << 2)
#define tcp_hdr_options_size(hdr)     (((hdr)->doff - 5) << 2)
typedef int * tcp_pcb_t;
typedef uint8_t * tcp_server_pcb_t;

typedef struct tcp_client_info{
    ipv4_addr_t     local_addr;
    ipv4_addr_t     remote_addr;
    uint16_t        local_port;
    uint16_t        remote_port;
    ehip_netdev_t   *netdev;
}tcp_client_info_t;

/**
 * @brief                   tcp服务端创建
 * @param  bind_addr        绑定地址
 * @param  bind_port        绑定端口
 * @param  netdev           指定网络设备
 * @param  dst_addr         服务器地址
 * @param  dst_port         服务器端口
 * @param  rx_buf_size      rx缓冲区大小
 * @param  tx_buf_size      tx缓冲区大小
 * @return tcp_pcb_t        返回值需要使用 eh_ptr_to_error 进行错误码判断
 */
extern tcp_pcb_t ehip_tcp_client_new(ipv4_addr_t bind_addr, uint16_be_t bind_port, 
    ehip_netdev_t *netdev, ipv4_addr_t dst_addr, uint16_be_t dst_port, uint16_t rx_buf_size, uint16_t tx_buf_size);

/**
 * @brief                   tcp服务端创建
 * @param  bind_port        绑定端口      0表示随机
 * @param  dst_addr         服务器地址
 * @param  dst_port         服务器端口
 * @param  rx_buf_size      rx缓冲区大小
 * @param  tx_buf_size      tx缓冲区大小
 * @return tcp_pcb_t        返回值需要使用 eh_ptr_to_error 进行错误码判断
 */
extern tcp_pcb_t ehip_tcp_client_any_new(uint16_be_t bind_port, ipv4_addr_t dst_addr, 
    uint16_be_t dst_port, uint16_t rx_buf_size, uint16_t tx_buf_size);

extern void ehip_tcp_client_delete(tcp_pcb_t pcb);

extern void ehip_tcp_client_get_info(tcp_pcb_t pcb, tcp_client_info_t *info);

extern void ehip_tcp_set_events_callback(tcp_pcb_t pcb,
    void (*events_callback)(tcp_pcb_t pcb, enum tcp_event state));

extern int ehip_tcp_client_connect(tcp_pcb_t pcb);
extern int ehip_tcp_client_disconnect(tcp_pcb_t pcb);

extern void ehip_tcp_client_set_userdata(tcp_pcb_t pcb, void *userdata);
extern void *ehip_tcp_client_get_userdata(tcp_pcb_t pcb);

extern eh_ringbuf_t *ehip_tcp_client_get_send_ringbuf(tcp_pcb_t pcb);
extern eh_ringbuf_t *ehip_tcp_client_get_recv_ringbuf(tcp_pcb_t pcb);

extern int ehip_tcp_client_request_send(tcp_pcb_t pcb);



extern tcp_server_pcb_t ehip_tcp_server_new(ipv4_addr_t bind_addr, uint16_be_t bind_port, ehip_netdev_t *netdev, uint16_t rx_buf_size, uint16_t tx_buf_size);
extern tcp_server_pcb_t ehip_tcp_server_any_new(uint16_be_t bind_port, uint16_t rx_buf_size, uint16_t tx_buf_size);
extern void ehip_tcp_server_delete(tcp_server_pcb_t pcb);
extern int ehip_tcp_server_listen(tcp_server_pcb_t pcb);
extern void ehip_tcp_server_set_new_connect_callback(tcp_server_pcb_t pcb, void (*new_connect)(tcp_pcb_t new_client));



#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _TCP_H_