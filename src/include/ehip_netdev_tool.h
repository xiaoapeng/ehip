/**
 * @file ehip_netdev_tool.h
 * @brief 网络设备控制工具
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-11-05
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */

#ifndef _EHIP_NETDEV_TOOL_H_
#define _EHIP_NETDEV_TOOL_H_

#include <stdint.h>
#include <ehip_netdev.h>
#include <ehip-mac/ethernet.h>
#include <ehip-ipv4/ip.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */
#define EHIP_NETDEV_INFO_NAME_MAX   16U
typedef struct ipv4_netdev_info {
    // IPV4_ATTR_FLAG_X
    uint32_t        attr_flags;
    ipv4_addr_t     ipv4_addr[EHIP_NETDEV_MAX_IP_NUM];
    ipv4_addr_t     ipv4_mask[EHIP_NETDEV_MAX_IP_NUM];
    uint8_t         ipv4_addr_num;
}ipv4_netdev_info_t;

typedef struct ehip_netdev_info{
    char  name[EHIP_NETDEV_INFO_NAME_MAX];
    enum ehip_netdev_type  type;
    /* EHIP_NETDEV_STATUS_XX */
    eh_flags_t             status;
    uint16_t               mtu;
    
    union{
        struct{
            ehip_eth_addr_t hw_addr;
            ehip_eth_addr_t broadcast_hw_addr;
            // ehip_eth_addr_t multicast_hw_addr[ETH_MULTICAST_ADDR_NUM];
            ipv4_netdev_info_t ipv4_info;
        }ethernet;
        struct{
            ipv4_netdev_info_t ipv4_info;
        }loopback;
        struct{
            ipv4_netdev_info_t ipv4_info;
        }tun;
    };
}ehip_netdev_info_t;


/**
 * @brief                   网络设备 UP
 * @param  netdev
 * @return int 
 */
static inline int ehip_netdev_tool_up(ehip_netdev_t *netdev){
    return ehip_netdev_up(netdev);
}

/**
 * @brief                   网络设备 DOWN
 * @param  netdev
 * @return int 
 */
static inline void ehip_netdev_tool_down(ehip_netdev_t *netdev){
    ehip_netdev_down(netdev);
}

/**
 * @brief                   遍历所有注册的网卡
 * @param  netdev           上次遍历返回的网卡句柄，第一次遍历传入NULL
 * @return ehip_netdev_t*   返回值为NULL时遍历结束
 */
static inline ehip_netdev_t * ehip_netdev_tool_iterate(ehip_netdev_t *netdev){
    return ehip_netdev_iterate(netdev);
}

/**
 * @brief                   网络设备控制
 * @param  netdev
 * @param  ctrl
 * @param  arg
 * @return int 
 */
extern int ehip_netdev_tool_ctrl(ehip_netdev_t *netdev, uint32_t ctrl, void *arg);

/**
 * @brief                   获取网络设备信息
 * @param  netdev           网卡句柄
 * @param  info             网络设备信息结构体指针
 * @return int 
 */
extern int ehip_netdev_tool_get_info(ehip_netdev_t *netdev, ehip_netdev_info_t *info);

/**
 * @brief                   根据网卡名称获取网卡句柄
 * @param  netdev_name      网卡注册时名称
 * @return ehip_netdev_t* 
 */
static inline ehip_netdev_t * ehip_netdev_tool_find(const char *netdev_name){
    return ehip_netdev_find(netdev_name);
}




#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _EHIP_NETDEV_TOOL_H_
