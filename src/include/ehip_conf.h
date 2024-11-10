/**
 * @file ehip_conf.h
 * @brief ehip_conf的默认配置
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-10-13
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */
#ifndef _EHIP_CONF_H_
#define _EHIP_CONF_H_

/*
 * 以太网帧内存块大小
 */
#ifndef EHIP_NETDEV_TYPE_ETHERNET_POOL_BUFFER_SIZE
#define EHIP_NETDEV_TYPE_ETHERNET_POOL_BUFFER_SIZE              1518U
#endif

/*
 * 以太网帧内存块数量
 */
#ifndef EHIP_NETDEV_TYPE_ETHERNET_POOL_BUFFER_NUM
#define EHIP_NETDEV_TYPE_ETHERNET_POOL_BUFFER_NUM               6U
#endif

/**
 * 以太网帧内存块对齐大小
 */
#ifndef EHIP_NETDEV_TYPE_ETHERNET_POOL_BUFFER_ALIGN
#define EHIP_NETDEV_TYPE_ETHERNET_POOL_BUFFER_ALIGN             16U
#endif

/*
 *  POLL BUFFER 句柄最大数量，要大于 EHIP_NETDEV_TYPE_ETHERNET_POOL_BUFFER_NUM
 */
#ifndef EHIP_NETDEV_POLL_BUFFER_MAX_NUM 
#define EHIP_NETDEV_POLL_BUFFER_MAX_NUM                         16U
#endif

/**
 *  网卡RX 消息句柄数量，单次最多结束的数据包数量
 */
#ifndef EHIP_CORE_MBOX_NETDEV_MSG_BUFFER_NUM
#define EHIP_CORE_MBOX_NETDEV_MSG_BUFFER_NUM                    16U
#endif

/**
 *  内存池基础数据结构对齐
 */
#ifndef EHIP_POOL_BASE_ALIGN
#define EHIP_POOL_BASE_ALIGN                                    4U
#endif

/**
 * 网络设备支持最多ip数量
 */
#ifndef EHIP_NETDEV_MAX_IP_NUM
#define EHIP_NETDEV_MAX_IP_NUM                                  4U
#endif

/**
 * 支持最多的多播地址数量
 */
#ifndef ETH_MULTICAST_ADDR_NUM
#define ETH_MULTICAST_ADDR_NUM                                  16U
#endif


#endif // _EHIP_CONF_H_