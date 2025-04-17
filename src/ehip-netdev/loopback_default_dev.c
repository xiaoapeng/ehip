/**
 * @file loopback_default_dev.c
 * @brief 默认的lo设备
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-04-04
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */

#include <eh.h>
#include <eh_error.h>
#include <ehip_core.h>
#include <ehip_conf.h>
#include <ehip_module.h>
#include <ehip_buffer.h>
#include <ehip_netdev.h>
#include <ehip_netdev_tool.h>
#include <ehip-mac/loopback.h>
ehip_netdev_t *_lo_netdev;

static int loopback_default_up(ehip_netdev_t *netdev){
    (void)netdev;
    return 0;
}

static void loopback_default_down(ehip_netdev_t *netdev){
    (void)netdev;
}


static int loopback_default_ctrl(ehip_netdev_t *netdev, uint32_t cmd, void *arg){
    (void)netdev;
    (void)cmd;
    (void)arg;
    return -1;
}

static int loopback_default_start_xmit(ehip_netdev_t *netdev, ehip_buffer_t *buf){
    (void)netdev;
    struct loopback_hdr *loopback_hdr;
    loopback_hdr = (struct loopback_hdr *)ehip_buffer_get_payload_ptr(buf);
    if(loopback_hdr == NULL)
        goto drop;
    /* 与正常网卡的处理方式不同，这里直接剥去头部，直接送往3层 */
    buf->protocol = loopback_hdr->type;
    buf->packet_type = EHIP_PACKET_TYPE_LOOPBACK;
    buf->netdev = loopback_hdr->virtual_hw_addr;
    ehip_buffer_head_reduce(buf, sizeof(struct loopback_hdr));
    ehip_rx(buf);
    return EH_RET_OK;
drop:
    ehip_buffer_free(buf);
    return EH_RET_OK;
}

static void loopback_default_tx_timeout(ehip_netdev_t *netdev){
    (void)netdev;
    return ;
}


static struct ehip_netdev_ops  loopback_default_ops = {
    .ndo_up = loopback_default_up,
    .ndo_down = loopback_default_down,
    .ndo_ctrl = loopback_default_ctrl,
    .ndo_start_xmit = loopback_default_start_xmit,
    .ndo_tx_timeout = loopback_default_tx_timeout,
};

static const struct ehip_netdev_param loopback_default_param = {
    .name = "lo",
    .net_max_frame_size = EHIP_NETDEV_TYPE_GENERAL_POOL_BUFFER_SIZE,
    .ops = &loopback_default_ops,
    .userdata = NULL
};

static int __init loopback_default_dev_init(void)
{
    _lo_netdev = ehip_netdev_register(EHIP_NETDEV_TYPE_LOOPBACK, &loopback_default_param);
    return eh_ptr_to_error(_lo_netdev);
}

static void __exit loopback_default_dev_exit(void)
{
    ehip_netdev_unregister(_lo_netdev);
}

ehip_netdev_module_export(loopback_default_dev_init, loopback_default_dev_exit);
