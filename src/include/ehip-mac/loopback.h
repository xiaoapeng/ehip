/**
 * @file loopback.h
 * @brief 定义回环设备的虚拟头部
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-04-06
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */
#ifndef _LOOPBACK_H_
#define _LOOPBACK_H_

#include <stdint.h>
#include <eh_types.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */


#define EHIP_LOOPBACK_HWADDR_LEN                sizeof(ehip_netdev_t *)

typedef struct ehip_netdev ehip_netdev_t;

struct __packed loopback_hdr {
    ehip_netdev_t *virtual_hw_addr; /* 虚拟物理地址，实际就是被回环的网卡指针 */
    uint16_t       type;            /* 帧类型 */
};

extern ehip_netdev_t *_lo_netdev;

#define loopback_default_netdev()             (_lo_netdev)

#define loopback_is_loopback_netdev(netdev)   ((netdev) == _lo_netdev)


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _LOOPBACK_H_