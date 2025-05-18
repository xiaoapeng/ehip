/**
 * @file route_refresh.c
 * @brief 路由刷新函数
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-05-18
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */


#include <ehip_core.h>
#include <ehip_error.h>
#include <ehip_netdev.h>
#include <ehip_netdev_trait.h>
#include <ehip-ipv4/route.h>
#include <ehip-ipv4/route_refresh.h>
#include <ehip-ipv4/ip.h>
#include <ehip-mac/loopback.h>

int ehip_route_refresh(ehip_netdev_t **dev_ptr, ipv4_addr_t *src_addr_ptr, ipv4_addr_t dst_addr, ipv4_addr_t *gw,
        enum route_table_type *route_type_ptr, uint32_t *last_route_trait_value, uint32_t flags)
{
    enum route_table_type route_type = *route_type_ptr;
    ehip_netdev_t *dev = *dev_ptr;
    ipv4_addr_t src_addr = *src_addr_ptr;
    if(  route_type == ROUTE_TABLE_UNKNOWN || 
         ipv4_route_table_is_changed(*last_route_trait_value)){
        /* 重新路由 */
        struct route_info route;
        ipv4_addr_t best_src_addr;

        *route_type_ptr = route_type = ipv4_route_lookup(dst_addr, dev, &route, &best_src_addr);
        *last_route_trait_value = ipv4_route_table_get_trait_value();
        if(route_type == ROUTE_TABLE_UNREACHABLE)
            return EHIP_RET_UNREACHABLE;
        *dev_ptr = dev = route.netdev;
        /* 
         * dev == NULL的情况一般不会出现，除非 *dev_ptr == NULL &&  dst_addr == 255.255.255.255 
         * 如果出现这种情况，将视为错误的状态
         */
        if( dev == NULL){
            *route_type_ptr = ROUTE_TABLE_UNREACHABLE;
            return EH_RET_INVALID_STATE;
        }

        /* 刷新源地址 */
        if(flags & ROUTE_REFRESH_FLAGS_REFRESH_SRC_ADDR){
            if( !(flags & ROUTE_REFRESH_FLAGS_ALLOW_SRC_ADDR_CHANGE) && src_addr && src_addr != best_src_addr){
                /* 没有设置允许源地址改变的flag,若发现源地址发生变化则返回错误 */
                *route_type_ptr = ROUTE_TABLE_UNREACHABLE;
                return EH_RET_INVALID_STATE;
            }
            *src_addr_ptr = src_addr = best_src_addr;
            flags &= ~ROUTE_REFRESH_FLAGS_CHECKED_SRC_ADDR;
        }

        *gw = route.gateway;
    }

    switch(route_type){
        case ROUTE_TABLE_MULTICAST:
            if(!(flags & ROUTE_REFRESH_FLAGS_ALLOW_MULTICAST))
                return EHIP_RET_UNREACHABLE;
            break;
        case ROUTE_TABLE_BROADCAST:
            if(!(flags & ROUTE_REFRESH_FLAGS_ALLOW_BROADCAST))
                return EHIP_RET_UNREACHABLE;
            break;
        case ROUTE_TABLE_UNICAST:
            if(!(flags & ROUTE_REFRESH_FLAGS_ALLOW_UNICAST))
                return EHIP_RET_UNREACHABLE;
            break;
        case ROUTE_TABLE_LOCAL:
        case ROUTE_TABLE_LOCAL_SELF:
            if(!(flags & ROUTE_REFRESH_FLAGS_ALLOW_LOOPBACK))
                return EHIP_RET_UNREACHABLE;
            if(!ipv4_netdev_flags_is_loopback_support(ehip_netdev_trait_ipv4_dev(dev)))
                return EH_RET_NOT_SUPPORTED;
            if(!(ehip_netdev_flags_get(loopback_default_netdev()) & EHIP_NETDEV_STATUS_UP))
                return EHIP_RET_UNREACHABLE;
            break;
    default:
        return EHIP_RET_UNREACHABLE;
    }
    
    /* 源地址检查 */
    if(flags & ROUTE_REFRESH_FLAGS_CHECKED_SRC_ADDR && 
        !ipv4_netdev_is_ipv4_addr_valid(ehip_netdev_trait_ipv4_dev(dev), src_addr)){
        return EHIP_RET_UNREACHABLE;
    }

    if(!(ehip_netdev_flags_get(dev) & EHIP_NETDEV_STATUS_UP))
        return EHIP_RET_UNREACHABLE;
    return 0;
}