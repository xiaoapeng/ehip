/**
 * @file loopback_dev.c
 * @brief 回环设备类型
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-04-04
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */

#include <ehip_module.h>
#include <ehip_netdev_trait.h>
#include <ehip-netdev-class/loopback_dev.h>
#include <ehip-mac/loopback.h>


static int  loopback_dev_trait_up(ehip_netdev_t *netdev);
static void loopback_dev_trait_down(ehip_netdev_t *netdev);
static void loopback_dev_trait_reset(ehip_netdev_t *netdev);
static int  loopback_dev_trait_change(ehip_netdev_t *netdev, const void *type_ptr, const void *src_ptr);
static int  loopback_dev_trait_hard_header(ehip_netdev_t *netdev, ehip_buffer_t *buf, 
    const ehip_hw_addr_t *src_hw_addr, const ehip_hw_addr_t *dst_hw_addr, 
    enum ehip_ptype ptype, ehip_buffer_size_t len);
static int  loopback_dev_trait_buffer_padding(ehip_netdev_t *netdev, ehip_buffer_t *buf);

const struct ehip_netdev_trait_ops loopback_dev_trait_ops = {
    .trait_size = sizeof(struct loopback_trait),
    .up = loopback_dev_trait_up,
    .down = loopback_dev_trait_down,
    .reset = loopback_dev_trait_reset,
    .change = loopback_dev_trait_change,
    .hard_header = loopback_dev_trait_hard_header,
    .buffer_padding = loopback_dev_trait_buffer_padding,
    .hw_addr_offset = EHIP_NETDEV_TRAIT_UNKNOWN_OFFSET,
    .mac_ptype_offset = EHIP_NETDEV_TRAIT_UNKNOWN_OFFSET,
    .ipv4_dev_offset = ehip_netdev_trait_offsetof(struct loopback_trait, ipv4_netdev),
    .multicast_hw_offset = EHIP_NETDEV_TRAIT_UNKNOWN_OFFSET,
    .broadcast_hw_offset = EHIP_NETDEV_TRAIT_UNKNOWN_OFFSET,
};


int loopback_dev_trait_change(ehip_netdev_t *netdev, const void *type_ptr, const void *src_ptr){
    // struct loopback_trait *netdev_loopback_trait = (struct loopback_trait *)ehip_netdev_to_trait(netdev);
    long long_offset = (long)type_ptr-(long)netdev;
    uint16_t offset;
    int ret = 0;
    if(long_offset >= (long)(sizeof(ehip_netdev_t) + sizeof(struct loopback_trait))){
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


static int loopback_dev_trait_up(ehip_netdev_t *netdev){
    struct loopback_trait *netdev_loopback_trait = (struct loopback_trait *)ehip_netdev_to_trait(netdev);
    _ipv4_netdev_up(&netdev_loopback_trait->ipv4_netdev);
    return 0;
}
static void loopback_dev_trait_down(ehip_netdev_t *netdev){
    struct loopback_trait *netdev_loopback_trait = (struct loopback_trait *)ehip_netdev_to_trait(netdev);
    _ipv4_netdev_down(&netdev_loopback_trait->ipv4_netdev);
}

static void loopback_dev_trait_reset(ehip_netdev_t *netdev){
    struct loopback_trait *netdev_loopback_trait = (struct loopback_trait *)ehip_netdev_to_trait(netdev);
    memset(netdev_loopback_trait, 0, sizeof(struct loopback_trait));
    netdev->attr.hw_addr_len = EHIP_LOOPBACK_HWADDR_LEN;        /* loopback 使用虚拟的物理地址(网卡指针) */
    netdev->attr.hw_head_size = sizeof(struct loopback_hdr);
    netdev->attr.hw_tail_size = 0;
    netdev->attr.mtu = (uint16_t)(netdev->param->net_max_frame_size - 
        netdev->attr.hw_head_size - netdev->attr.hw_tail_size);
    netdev->attr.buffer_type = EHIP_BUFFER_TYPE_GENERAL_FRAME;
    _ipv4_netdev_reset(&netdev_loopback_trait->ipv4_netdev, netdev);
    ipv4_netdev_flags_set(&netdev_loopback_trait->ipv4_netdev, IPV4_ATTR_FLAG_ARP_SUPPORT|IPV4_ATTR_FLAG_LOOPBACK_SUPPORT);

}


static int  loopback_dev_trait_hard_header(ehip_netdev_t *netdev, ehip_buffer_t *buf, 
    const ehip_hw_addr_t *src_hw_addr, const ehip_hw_addr_t *dst_hw_addr, 
    enum ehip_ptype ptype, ehip_buffer_size_t len){
    (void)netdev;
    (void)src_hw_addr;
    (void)len;
    struct loopback_hdr *netdev_virtual_hw_addr;

    netdev_virtual_hw_addr = (struct loopback_hdr *)ehip_buffer_head_append(buf, sizeof(struct loopback_hdr));
    if(netdev_virtual_hw_addr == NULL)
        return EH_RET_INVALID_STATE;
    memcpy(&netdev_virtual_hw_addr->virtual_hw_addr, dst_hw_addr, EHIP_LOOPBACK_HWADDR_LEN);
    netdev_virtual_hw_addr->type = (uint16_t)ptype;
    return EH_RET_OK;
}

static int loopback_dev_trait_buffer_padding(ehip_netdev_t *netdev, ehip_buffer_t *buf){
    (void)netdev;
    (void)buf;
    return EH_RET_OK;
}



static int __init loopback_dev_trait_init(void)
{
    return ehip_netdev_trait_type_install(EHIP_NETDEV_TYPE_LOOPBACK, &loopback_dev_trait_ops);
}

ehip_preinit_module_export(loopback_dev_trait_init, NULL);