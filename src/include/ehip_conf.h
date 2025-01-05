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
#define EHIP_NETDEV_TYPE_ETHERNET_POOL_BUFFER_NUM               12U
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
#define EHIP_NETDEV_POLL_BUFFER_MAX_NUM                         32U
#endif

/**
 *  网卡RX 消息句柄数量，单次最多接收的数据包数量
 */
#ifndef EHIP_CORE_MBOX_NETDEV_RX_MSG_BUFFER_NUM
#define EHIP_CORE_MBOX_NETDEV_RX_MSG_BUFFER_NUM                 16U
#endif

/**
 *  网卡TX 消息句柄数量，单次最多可发送的数据包数量
 */
#ifndef EHIP_CORE_MBOX_NETDEV_TX_MSG_BUFFER_NUM
#define EHIP_CORE_MBOX_NETDEV_TX_MSG_BUFFER_NUM                 16U
#endif

/**
 *  IPV4最大支持分配的数据包数量
 */
#ifndef EHIP_IP_MAX_BUFFER_NUM
#define EHIP_IP_MAX_BUFFER_NUM                                  16U
#endif

/*
 *  IPV4支持同一时间分片重组最大数
 */
#ifndef EHIP_IP_MAX_IP_FRAGMENT_BUFFER_NUM
#define EHIP_IP_MAX_IP_FRAGMENT_BUFFER_NUM                      8U
#endif

#ifndef EHIP_IP_MAX_IP_OPTIONS_BYTES_BUFFER_NUM
#define EHIP_IP_MAX_IP_OPTIONS_BYTES_BUFFER_NUM                 8U
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

/* 网络设备数据发送看门狗超时时间 */
#ifndef EHIP_NETDEV_TX_WATCHDOG_TIMEOUT
#define EHIP_NETDEV_TX_WATCHDOG_TIMEOUT                         5000U
#endif

/* mac地址最大长度 */
#ifndef EHIP_ETH_HWADDR_MAX_LEN
#define EHIP_ETH_HWADDR_MAX_LEN                                 6U
#endif

/* arp缓存项最大数量 */
#ifndef EHIP_ARP_CACHE_MAX_NUM
#define EHIP_ARP_CACHE_MAX_NUM                                  16U
#endif

/* arp重试次数 */
#ifndef EHIP_ARP_MAX_RETRY_CNT
#define EHIP_ARP_MAX_RETRY_CNT                                  5U
#endif

/* arp delay_probe_time 时间 */
#ifndef EHIP_ARP_DELAY_PROBE_TIME
#define EHIP_ARP_DELAY_PROBE_TIME                               2U
#endif

/* reachable_time 时间 */
#ifndef EHIP_ARP_REACHABLE_TIME
#define EHIP_ARP_REACHABLE_TIME                                 300U
#endif

#ifndef EHIP_ARP_DEBUG
#define EHIP_ARP_DEBUG                                          0U
#endif

#ifndef EHIP_IP_DEBUG
#define EHIP_IP_DEBUG                                           0U
#endif

#ifndef EHIP_ETHERNET_V2_DEBUG
#define EHIP_ETHERNET_V2_DEBUG                                  0U
#endif


/* 最大IP分片数 */
#ifndef EHIP_IP_MAX_FRAGMENT_NUM
#define EHIP_IP_MAX_FRAGMENT_NUM                                4U
#endif

/* IP分片超时时间, 最大255 */
#ifndef EHIP_IP_FRAGMENT_TIMEOUT
#define EHIP_IP_FRAGMENT_TIMEOUT                                15
#endif


#endif // _EHIP_CONF_H_