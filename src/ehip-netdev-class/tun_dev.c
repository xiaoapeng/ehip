/**
 * @file tun_dev.c
 * @brief tun 设备类实现
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-12-21
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */

#include <ehip_module.h>
#include <ehip_netdev_trait.h>
#include <ehip-netdev-class/tun_dev.h>

static int  tun_dev_trait_up(ehip_netdev_t *netdev);
static void tun_dev_trait_down(ehip_netdev_t *netdev);
static void tun_dev_trait_reset(ehip_netdev_t *netdev);
static int  tun_dev_trait_change(ehip_netdev_t *netdev, const void *type_ptr, const void *src_ptr);
static int  tun_dev_trait_hard_header(ehip_netdev_t *netdev, ehip_buffer_t *buf, 
    const ehip_hw_addr_t *src_hw_addr, const ehip_hw_addr_t *dst_hw_addr, 
    enum ehip_ptype ptype, ehip_buffer_size_t len);
static int  tun_dev_trait_buffer_padding(ehip_netdev_t *netdev, ehip_buffer_t *buf);

const struct ehip_netdev_trait_ops tun_dev_trait_ops = {
    .trait_size = sizeof(struct tun_trait),
    .up = tun_dev_trait_up,
    .down = tun_dev_trait_down,
    .reset = tun_dev_trait_reset,
    .change = tun_dev_trait_change,
    .hard_header = tun_dev_trait_hard_header,
    .buffer_padding = tun_dev_trait_buffer_padding,
    .hw_addr_offset = EHIP_NETDEV_TRAIT_UNKNOWN_OFFSET,
    .mac_ptype_offset = EHIP_NETDEV_TRAIT_UNKNOWN_OFFSET,
    .ipv4_dev_offset = ehip_netdev_trait_offsetof(struct tun_trait, ipv4_netdev),
    .broadcast_hw_offset = EHIP_NETDEV_TRAIT_UNKNOWN_OFFSET,
    .multicast_hw_offset = EHIP_NETDEV_TRAIT_UNKNOWN_OFFSET,
};

int tun_dev_trait_change(ehip_netdev_t *netdev, const void *type_ptr, const void *src_ptr){
    long long_offset = (long)type_ptr-(long)netdev;
    uint16_t offset;
    int ret = 0;
    if(long_offset >= (long)(sizeof(ehip_netdev_t) + sizeof(struct tun_trait))){
        return EH_RET_INVALID_PARAM;
    }
    offset = (uint16_t)long_offset;
    switch (offset) {
        case ehip_netdev_attr_offsetof(mtu):{
            uint16_t new_mtu = *(uint16_t*)src_ptr;
            if(new_mtu < 46 || (new_mtu + netdev->attr.hw_tail_size + netdev->attr.hw_head_size) > netdev->param->net_max_frame_size){
                ret = EH_RET_NOT_SUPPORTED;
                break;
            }
            netdev->attr.mtu = new_mtu;
            break;
        }
        default:
            ret = EH_RET_INVALID_PARAM;
            break;
    }
    return ret;
}

static int tun_dev_trait_up(ehip_netdev_t *netdev){
    struct tun_trait *netdev_tun_trait = (struct tun_trait *)ehip_netdev_to_trait(netdev);
    _ipv4_netdev_up(&netdev_tun_trait->ipv4_netdev);
    return 0;
}
static void tun_dev_trait_down(ehip_netdev_t *netdev){
    struct tun_trait *netdev_tun_trait = (struct tun_trait *)ehip_netdev_to_trait(netdev);
    _ipv4_netdev_down(&netdev_tun_trait->ipv4_netdev);
}

static void tun_dev_trait_reset(ehip_netdev_t *netdev){
    struct tun_trait *netdev_tun_trait = (struct tun_trait *)ehip_netdev_to_trait(netdev);
    memset(netdev_tun_trait, 0, sizeof(struct tun_trait));
    netdev->attr.hw_addr_len = 0;
    if(netdev->param->trait_param){
        struct tun_trait_param *tun_trait_param = (struct tun_trait_param *)netdev->param->trait_param;
        netdev->attr.hw_head_size = tun_trait_param->hw_head_size;
        netdev->attr.hw_tail_size = tun_trait_param->hw_tail_size;
    }
    else{
        netdev->attr.hw_head_size = 0;
        netdev->attr.hw_tail_size = 0;
    }
    netdev->attr.mtu = (uint16_t)(netdev->param->net_max_frame_size - 
        netdev->attr.hw_head_size - netdev->attr.hw_tail_size);
    netdev->attr.buffer_type = EHIP_BUFFER_TYPE_GENERAL_FRAME;
    _ipv4_netdev_reset(&netdev_tun_trait->ipv4_netdev, netdev);
}

static int tun_dev_trait_hard_header(ehip_netdev_t *netdev, ehip_buffer_t *buf, 
    const ehip_hw_addr_t *src_hw_addr, const ehip_hw_addr_t *dst_hw_addr, 
    enum ehip_ptype ptype, ehip_buffer_size_t len){
    (void)netdev;
    (void)buf;
    (void)src_hw_addr;
    (void)dst_hw_addr;
    (void)ptype;
    (void)len;
    return EH_RET_OK;
}

static int tun_dev_trait_buffer_padding(ehip_netdev_t *netdev, ehip_buffer_t *buf){
    (void)netdev;
    (void)buf;
    return EH_RET_OK;
}

static int __init tun_dev_trait_init(void)
{
    return ehip_netdev_trait_type_install(EHIP_NETDEV_TYPE_TUN, &tun_dev_trait_ops);
}
ehip_preinit_module_export(tun_dev_trait_init, NULL);