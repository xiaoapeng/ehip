/**
 * @file ehip_netdev_tool.c
 * @brief 网络设备控制工具
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-11-05
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 

 */

#include <eh_error.h>
#include <ehip_netdev_tool.h>
#include <ehip_netdev_trait.h>


int ehip_netdev_tool_ctrl(ehip_netdev_t *netdev, uint32_t ctrl, void *arg){
    if(netdev && netdev->param && netdev->param->ops && netdev->param->ops->ndo_ctrl)
        return netdev->param->ops->ndo_ctrl(netdev, ctrl, arg);
    return EH_RET_INVALID_PARAM;
}


/**
 * @brief 填充IPv4设备信息到网络设备信息结构体
 * @param ipv4_dev IPv4设备结构体指针
 * @param ipv4_info 要填充的IPv4信息结构体指针
 * @return int 成功返回EH_RET_OK，失败返回错误码
 */
static int _fill_ipv4_netdev_info(struct ipv4_netdev* ipv4_dev, ipv4_netdev_info_t* ipv4_info){
    ipv4_info->attr_flags = ipv4_dev->attr_flags;
    ipv4_info->ipv4_addr_num = ipv4_dev->ipv4_addr_num;
    for (size_t i = 0; i < ipv4_dev->ipv4_addr_num && i < EHIP_NETDEV_MAX_IP_NUM; i++) {
        ipv4_info->ipv4_addr[i] = ipv4_dev->ipv4_addr[i];
        ipv4_info->ipv4_mask[i] = ipv4_mask_len_to_mask(ipv4_dev->ipv4_mask_len[i]);
    }
    return EH_RET_OK;
}

int ehip_netdev_tool_get_info(ehip_netdev_t *netdev, ehip_netdev_info_t *info){
    struct ipv4_netdev* ipv4_dev;
    if(!netdev || !info) {
        return EH_RET_INVALID_PARAM;
    }
    
    memset(info, 0, sizeof(ehip_netdev_info_t));

    strncpy((char*)info->name, netdev->param->name, EHIP_NETDEV_INFO_NAME_MAX - 1);
    info->name[EHIP_NETDEV_INFO_NAME_MAX - 1] = '\0';
    info->type = netdev->type;
    info->status = ehip_netdev_flags_get(netdev);
    info->mtu = netdev->attr.mtu;

    ipv4_dev = ehip_netdev_trait_ipv4_dev(netdev);

    switch(netdev->type){
        case EHIP_NETDEV_TYPE_ETHERNET:{
            const ehip_hw_addr_t* hw_addr = ehip_netdev_trait_hw_addr(netdev);
            const ehip_hw_addr_t* broadcast_hw = ehip_netdev_trait_broadcast_hw(netdev);
            
            if(hw_addr)
                memcpy(&info->ethernet.hw_addr, hw_addr, sizeof(ehip_eth_addr_t));
            if(broadcast_hw)
                memcpy(&info->ethernet.broadcast_hw_addr, broadcast_hw, sizeof(ehip_eth_addr_t));

            if(ipv4_dev)
                _fill_ipv4_netdev_info(ipv4_dev, &info->ethernet.ipv4_info);
            break;
        }
        case EHIP_NETDEV_TYPE_LOOPBACK:{
            if(ipv4_dev)
                _fill_ipv4_netdev_info(ipv4_dev, &info->loopback.ipv4_info);
            break;
        }
        case EHIP_NETDEV_TYPE_TUN:{
            if(ipv4_dev)
                _fill_ipv4_netdev_info(ipv4_dev, &info->tun.ipv4_info);
            break;
        }
        default:
            // 未知设备类型
            return EH_RET_INVALID_PARAM;
    }
    
    return EH_RET_OK;
}
