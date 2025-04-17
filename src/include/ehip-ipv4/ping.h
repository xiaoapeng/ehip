/**
 * @file ping.h
 * @brief 
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-01-21
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */

#ifndef _IPV4_PING_H_
#define _IPV4_PING_H_

#include <ehip-ipv4/ip.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

typedef int* ping_pcb_t;

/**
 * @brief                   new一个ping_pcb
 * @param  src_addr         源地址，必须是ipv4_netdev_get_addr或者ipv4_netdev_get_ipv4_addr_idx得到的ip地址
 * @param  dst_addr         目标地址
 * @param  netdev           已经up的网络设备
 * @return ping_pcb_t 
 */
extern ping_pcb_t ehip_ping_new(ipv4_addr_t src_addr, ipv4_addr_t dst_addr, ehip_netdev_t *netdev);

/**
 * @brief                   new一个ping_pcb
 * @param  dst_addr         目标地址
 * @return ping_pcb_t 
 */
extern ping_pcb_t ehip_ping_any_new(ipv4_addr_t dst_addr);

/**
 * @brief                   删除ping_pcb
 * @param  pcb              ping_pcb
 */
extern void ehip_ping_delete(ping_pcb_t pcb);

/**
 * @brief                   设置ping_pcb的用户数据
 * @param  pcb              ping_pcb
 * @param  userdata         用户数据
 */
extern void ehip_ping_set_userdata(ping_pcb_t pcb, void *userdata);

/**
 * @brief                   设置ping_pcb的timeout
 * @param  pcb              ping_pcb
 * @param  timeout_100ms    timeout，单位为100ms
 */
extern void ehip_ping_set_timeout(ping_pcb_t pcb, uint8_t timeout_100ms);

/**
 * @brief                   设置ping_pcb的ttl
 * @param  pcb              ping_pcb
 * @param  ttl              ttl
 */
extern void ehip_ping_set_ttl(ping_pcb_t pcb, uint8_t ttl);

/**
 * @brief                   设置ping_pcb的response回调
 * @param  pcb              ping_pcb
 * @param  response_callback    response回调
 */
extern void ehip_ping_set_response_callback(ping_pcb_t pcb, 
        void (*response_callback)(ping_pcb_t pcb, ipv4_addr_t addr, uint16_t seq, uint8_t ttl, eh_clock_t time_ms));

/**
 * @brief                   设置ping_pcb的error回调
 * @param  pcb              ping_pcb
 * @param  error_callback    error回调
 */
extern void ehip_ping_set_error_callback(ping_pcb_t pcb, 
        void (*error_callback)(ping_pcb_t pcb, ipv4_addr_t addr, uint16_t seq, int erron));

/**
 * @brief                   获取ping_pcb的用户数据
 * @param  pcb              ping_pcb
 * @return void* 
 */
extern void* ehip_ping_get_userdata(ping_pcb_t pcb);

/**
 * @brief                   发送ping请求
 * @param  pcb              ping_pcb
 * @param  data_len         ping数据长度
 * @return int 
 */
extern int ehip_ping_request(ping_pcb_t pcb, uint16_t data_len);

/**
 * @brief                   判断是否有活跃的ping请求
 * @param  pcb              ping_pcb
 * @return bool 
 */
extern bool ehip_ping_has_active_request(ping_pcb_t pcb);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _IPV4_PING_H_