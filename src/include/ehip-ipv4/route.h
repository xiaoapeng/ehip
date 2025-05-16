/**
 * @file route.h
 * @brief ipv4 route实现
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-11-18
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */
#ifndef _ROUTE_H_
#define _ROUTE_H_

#include <stdint.h>
#include <eh_types.h>
#include <eh_list.h>
#include <eh_llist.h>
#include <ehip-ipv4/ip.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

enum route_table_type{
    ROUTE_TABLE_UNKNOWN = 0,          /* 未知 */
    ROUTE_TABLE_UNREACHABLE = 1,      /* 网络不可达 */
    ROUTE_TABLE_MULTICAST,            /* 多播 */
    ROUTE_TABLE_BROADCAST,            /* 广播 */
    ROUTE_TABLE_UNICAST,              /* 单播 */
    ROUTE_TABLE_LOCAL,                /* 本地地址 */
    ROUTE_TABLE_LOCAL_SELF,           /* 本接口地址 */
    ROUTE_TABLE_MAX,                  /* 本子网地址 */
};

eh_static_assert(ROUTE_TABLE_MAX <= UINT8_MAX, "Is not support route table type more than 255.");

struct route_info{
    struct ehip_netdev     *netdev;                 /* 路由项指向的网卡 */
    ipv4_addr_t             dst_addr;               /* 目标 */
    ipv4_addr_t             src_addr;               /* 源IP */
    ipv4_addr_t             gateway;                /* 网关 */
    uint16_t                metric;                 /* 路由条目的优先级 */
    uint8_t                 mask_len;               /* 目标掩码长度 */
};

extern uint32_t _route_trait_value;

EH_EXTERN_SIGNAL(sig_route_changed);

/**
 * @brief                   添加一条路由
 * @param  route            路由信息
 * @return int              成功返回0
 */
extern int ipv4_route_add(const struct route_info *route);

/**
 * @brief                   删除一条路由表项
 * @param  route            路由信息
 * @return int              成功返回0
 */
extern int ipv4_route_del(const struct route_info *route);

/**
 * @brief                   将路由表转成数组项
 * @param  route_array      使用完后需要释放
 * @return int 
 */
extern int ipv4_route_to_array(struct route_info **route_array);

/**
 * @brief                       查找路由
 * @param  dst_addr             目标地址
 * @param  dst_netdev_or_null   目标网卡，如果为NULL则可以匹配任意网卡
 * @param  route                路由表项信息
 * @param  best_src_addr        建议的最佳源地址
 * @return int                  成功返回  ROUTE_TABLE_XXX
 */
extern enum route_table_type ipv4_route_lookup(ipv4_addr_t dst_addr, const ehip_netdev_t *dst_netdev_or_null, 
        struct route_info *route, ipv4_addr_t *best_src_addr);

/**
 * @brief                   接收数据时路由验证
 * @param  src_addr         源地址
 * @param  dst_addr         目标地址
 * @param  netdev           网络设备
 * @param  route            下一跳路由，如果dst_addr不是本地IP，且找到下一跳则返回该路由
 * @return int              存在该路由通路返回0，不存在该路由通路返回负数
 */
enum route_table_type ipv4_route_input(ipv4_addr_t src_addr, ipv4_addr_t dst_addr, 
    ehip_netdev_t *netdev, struct route_info *route);

/**
 * @brief  判断路由表是否变化
 * @param  old_trait_value  路由表特征值
 * @return bool             路由表变化返回true，否则返回false
 */
static inline bool ipv4_route_table_is_changed(uint32_t old_trait_value){
    return _route_trait_value != old_trait_value;
}



/**
 * @brief  获取路由表现有特征值
 */
static inline uint32_t ipv4_route_table_get_trait_value(void){
    return _route_trait_value;
}


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _ROUTE_H_