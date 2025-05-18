/**
 * @file ip.c
 * @brief ipv4设备
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-11-21
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */
 
#include <string.h>
#include <eh_formatio.h>
#include <eh_list.h>
#include <eh_error.h>
#include <ehip_netdev.h>
#include <ehip-ipv4/ip.h>
#include <ehip_netdev_trait.h>

static struct eh_list_head s_ipv4_dev_head = EH_LIST_HEAD_INIT(s_ipv4_dev_head);

static uint8_t ipv4_addr_default_mask_len(ipv4_addr_t addr){
    return ipv4_is_class_a(addr) ? IPV4_ADDR_DEFAULT_CLASS_A_MASK_LEN :
        ipv4_is_class_b(addr) ? IPV4_ADDR_DEFAULT_CLASS_B_MASK_LEN : 
        ipv4_is_class_c(addr) ? IPV4_ADDR_DEFAULT_CLASS_C_MASK_LEN : 
        IPV4_ADDR_DEFAULT_CLASS_D_MASK_LEN;
}

bool ipv4_netdev_is_ipv4_addr_valid(const struct ipv4_netdev* ipv4_dev, ipv4_addr_t ipv4_addr){
    return ipv4_netdev_get_ipv4_addr_idx(ipv4_dev, ipv4_addr) < 0 ? false : true;
}


bool ipv4_netdev_is_local_broadcast(const struct ipv4_netdev* ipv4_dev,ipv4_addr_t ipv4_addr){
    int ip_idx;
    ip_idx = ipv4_netdev_get_best_ipv4_addr_idx(ipv4_dev, ipv4_addr);
    return ip_idx >= 0 && ipv4_is_local_broadcast(ipv4_addr, ipve_netdev_get_ipv4_addr_mask_len_by_idx(ipv4_dev, ip_idx));
}

// 通过目标IP匹配最好的IP地址索引
int ipv4_netdev_get_best_ipv4_addr_idx(const struct ipv4_netdev* ipv4_dev, ipv4_addr_t dst_addr){
    int i;
    uint32_t mask;

    for(i = 0; i < ipv4_dev->ipv4_addr_num; i++){
        mask = ipv4_mask_len_to_mask(ipv4_dev->ipv4_mask_len[i]);
        if( ipv4_dev->ipv4_addr[i] && 
            (ipv4_dev->ipv4_addr[i] & mask) == (dst_addr & mask)){
            return i;
        }
    }
    return -1;
}

int ipv4_netdev_get_ipv4_addr_idx(const struct ipv4_netdev* ipv4_dev, ipv4_addr_t ipv4_addr){
    int i;
    for(i = 0; i < ipv4_dev->ipv4_addr_num; i++){
        if(ipv4_dev->ipv4_addr[i] == ipv4_addr)
            return i;
    }
    return EH_RET_NOT_EXISTS;
}


ipv4_addr_t ipv4_netdev_get_addr(const struct ipv4_netdev* ipv4_dev){
    if(ipv4_dev && ipv4_dev->ipv4_addr_num)
        return ipv4_dev->ipv4_addr[0];
    return IPV4_ADDR_ANY;
}

int ipv4_netdev_set_main_addr(struct ipv4_netdev* ipv4_dev, ipv4_addr_t addr, uint8_t mask_len){
    if(ipv4_netdev_is_ipv4_addr_valid(ipv4_dev, addr))
        return EH_RET_EXISTS;
    if(ipv4_is_zeronet(addr) || ipv4_is_multicast(addr) || ipv4_is_global_bcast(addr))
        return EH_RET_INVALID_PARAM;
    ipv4_dev->ipv4_addr[0] = addr;
    ipv4_dev->ipv4_mask_len[0] = mask_len ? mask_len : ipv4_addr_default_mask_len(addr);
    if(ipv4_dev->ipv4_addr_num == 0)
        ipv4_dev->ipv4_addr_num = 1;
    return EH_RET_OK;
}

int ipv4_netdev_set_sub_addr(struct ipv4_netdev* ipv4_dev, ipv4_addr_t addr, uint8_t mask_len){
    if(ipv4_dev->ipv4_addr_num >= EHIP_NETDEV_MAX_IP_NUM)
        return EH_RET_BUSY;
    if(ipv4_is_zeronet(addr) || ipv4_is_multicast(addr) || ipv4_is_global_bcast(addr))
        return EH_RET_INVALID_PARAM;
    if(ipv4_netdev_is_ipv4_addr_valid(ipv4_dev, addr))
        return EH_RET_EXISTS;
    ipv4_dev->ipv4_addr[ipv4_dev->ipv4_addr_num] = addr;
    ipv4_dev->ipv4_mask_len[ipv4_dev->ipv4_addr_num] = mask_len ? mask_len : ipv4_addr_default_mask_len(addr);
    ipv4_dev->ipv4_addr_num++;
    return EH_RET_OK;
}

void ipv4_netdev_del_addr(struct ipv4_netdev* ipv4_dev, ipv4_addr_t addr){
    int i;
    int move_num;
    i = ipv4_netdev_get_ipv4_addr_idx(ipv4_dev, addr);
    if( i < 0 || 
        (move_num = ipv4_dev->ipv4_addr_num - ((uint8_t)i+1) <= 0)
    ) return ;
    memmove(ipv4_dev->ipv4_addr+i,  ipv4_dev->ipv4_addr+i+1,  (size_t)move_num * sizeof(ipv4_addr_t));
    memmove(ipv4_dev->ipv4_mask_len+i,  ipv4_dev->ipv4_mask_len+i+1, (size_t)move_num * sizeof(uint8_t));
    ipv4_dev->ipv4_addr_num--;
    return ;
}

struct ipv4_netdev* ipv4_find_netdev_from_ipv4(ipv4_addr_t addr){
    struct ipv4_netdev *pos;
    eh_list_for_each_entry(pos, &s_ipv4_dev_head, node){
        if(ipv4_netdev_is_ipv4_addr_valid(pos, addr))
            return pos;
    }
    return NULL;
}


void _ipv4_netdev_up(struct ipv4_netdev *netdev){
    eh_list_add(&netdev->node, &s_ipv4_dev_head);
}

void _ipv4_netdev_down(struct ipv4_netdev *netdev){
    eh_list_del(&netdev->node);
}
