/**
 * @file route_refresh.h
 * @brief 为各协议提供通用的路由刷新
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-05-18
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */
#ifndef _ROUTE_REFRESH_H_
#define _ROUTE_REFRESH_H_


#include <ehip_netdev.h>
#include <ehip-ipv4/route.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */


#define ROUTE_REFRESH_FLAGS_ALLOW_UNICAST               0x00000001U  /* 允许单播 */
#define ROUTE_REFRESH_FLAGS_ALLOW_MULTICAST             0x00000002U  /* 允许多播 */
#define ROUTE_REFRESH_FLAGS_ALLOW_BROADCAST             0x00000004U  /* 允许广播 */
#define ROUTE_REFRESH_FLAGS_ALLOW_LOOPBACK              0x00000008U  /* 允许回环 */
#define ROUTE_REFRESH_FLAGS_CHECKED_SRC_ADDR            0x00000010U  /* 检查源地址,只有在做DHCP客户端地址为0.0.0.0时不需要设置这个 */
#define ROUTE_REFRESH_FLAGS_REFRESH_SRC_ADDR            0x00000020U  /* 刷新源地址 */
#define ROUTE_REFRESH_FLAGS_ALLOW_SRC_ADDR_CHANGE       0x00000040U  /* 允许源地址改变,允许源地址和上一次不一样 */

int ehip_route_refresh(ehip_netdev_t **dev, ipv4_addr_t *src_addr, ipv4_addr_t dst_addr, ipv4_addr_t *gw,
    enum route_table_type *route_type, uint32_t *last_route_trait_value, uint32_t flags);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _ROUTE_REFRESH_H_