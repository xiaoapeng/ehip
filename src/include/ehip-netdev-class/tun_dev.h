/**
 * @file tun_dev.h
 * @brief tun 设备类定义
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-12-21
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */

#ifndef _TUN_DEV_H_
#define _TUN_DEV_H_

#include <ehip-ipv4/ip.h>
#include <ehip_netdev_trait.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */


struct tun_trait{
    struct ipv4_netdev ipv4_netdev;
};


struct tun_trait_param{
    uint16_t hw_head_size;
    uint16_t hw_tail_size;
};


ehip_netdev_trait_static_assert(struct tun_trait);


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _TUN_DEV_H_