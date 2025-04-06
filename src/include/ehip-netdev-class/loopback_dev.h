/**
 * @file loopback_dev.c
 * @brief 回环设备类型
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-04-04
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */
#ifndef _LOOPBACK_DEV_H_
#define _LOOPBACK_DEV_H_
 
#include <ehip-ipv4/ip.h>
#include <ehip_netdev_trait.h>

 #ifdef __cplusplus
 #if __cplusplus
 extern "C"{
 #endif
 #endif /* __cplusplus */
 
struct loopback_trait{
    struct ipv4_netdev ipv4_netdev;
};
 

ehip_netdev_trait_static_assert(struct loopback_trait);
 
 
 #ifdef __cplusplus
 #if __cplusplus
 }
 #endif
 #endif /* __cplusplus */
 
 
 #endif // _LOOPBACK_DEV_H_