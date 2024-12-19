/**
 * @file ip.c
 * @brief ip协议解析
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-12-18
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */

#include <ehip_buffer.h>
#include <ehip_protocol_handle.h>
#include <ehip-ipv4/ip.h>

static void ip_handle(struct ehip_buffer* buf){
    struct ip_hdr *ip_hdr;
    if( buf->packet_type == EHIP_PACKET_TYPE_HOST || 
        (ip_hdr = (struct ip_hdr *)ehip_buffer_head_reduce(buf, sizeof(struct ip_hdr))) == NULL ||
        ip_hdr->version != 4 ||
        ip_hdr->ihl < 5
    )
        goto drop;

    /* TODO  */



drop:
    ehip_buffer_free(buf);
}

static struct ehip_protocol_handle ip_protocol_handle = {
    .ptype = EHIP_PTYPE_ETHERNET_IP,
    .handle = ip_handle,
    .node = EH_LIST_HEAD_INIT(ip_protocol_handle.node),
};
//https://blog.csdn.net/wuheshi/article/details/103891902