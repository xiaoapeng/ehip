/**
 * @file ip.c
 * @brief ip协议解析
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-12-18
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */

#include <stdint.h>

#include <eh_debug.h>
#include <eh_swab.h>
#include <ehip_core.h>
#include <ehip_buffer.h>
#include <ehip_chksum.h>
#include <ehip_module.h>
#include <ehip_protocol_handle.h>
#include <ehip_netdev_trait.h>
#include <ehip-ipv4/route.h>
#include <ehip-ipv4/ip_message.h>
#include <ehip-ipv4/ip.h>

struct ip_message *ip_fragment_reasse_tab[EHIP_IP_MAX_IP_FRAGMENT_BUFFER_NUM];

static int ip_fragment_find(const struct ip_hdr *ip_hdr){
    uint8_t old_expires_cd = 0xFF;
    int old_index = -1;             /* 最旧的分片记录号 */
    int null_index = -1;            /* 空闲的分片记录号 */
    

    for(int i = 0; i < (int)EHIP_IP_MAX_IP_FRAGMENT_BUFFER_NUM; i++){
        if(ip_fragment_reasse_tab[i] == NULL){
            null_index = i;
            continue;
        }
        if( ip_fragment_reasse_tab[i]->ip_hdr.id == ip_hdr->id  && 
            ip_fragment_reasse_tab[i]->ip_hdr.src_addr == ip_hdr->src_addr &&
            ip_fragment_reasse_tab[i]->ip_hdr.dst_addr == ip_hdr->dst_addr &&
            ip_fragment_reasse_tab[i]->ip_hdr.protocol == ip_hdr->protocol
        ){
            return i;
        }
        if(old_index == -1 || ip_fragment_reasse_tab[i]->rx_fragment->expires_cd < old_expires_cd){
            old_expires_cd = ip_fragment_reasse_tab[i]->rx_fragment->expires_cd;
            old_index = i;
        }
    }
    if(null_index) return null_index;
    if(old_index == -1)
        return -1;
    /* 释放空闲的分片记录 */
    ip_message_free(ip_fragment_reasse_tab[old_index]);
    ip_fragment_reasse_tab[old_index] = NULL;
    return old_index;
}

static void ip_fragment_clean(void){
    for(int i = 0; i < (int)EHIP_IP_MAX_IP_FRAGMENT_BUFFER_NUM; i++){
        if(ip_fragment_reasse_tab[i] == NULL)
            continue;
        ip_message_free(ip_fragment_reasse_tab[i]);
        ip_fragment_reasse_tab[i] = NULL;
    }
}

static struct ip_message * ip_reasse(ehip_buffer_t *buffer, const struct ip_hdr *ip_hdr, enum route_table_type route_type){
    int index;
    int ret;
    struct ip_message* ip_msg = NULL;
    if((index = ip_fragment_find(ip_hdr)) < 0){
        eh_errfl("IP fragment buffer is full, drop fragment.");
        ehip_buffer_free(buffer);
        return NULL;
    }
    eh_mdebugln( IP_REASSE, "ip fragment index:%d", index);
    eh_mdebugln( IP_REASSE, "id:%d", eh_hton16(ip_hdr->id));
    eh_mdebugln( IP_REASSE, "src:%d.%d.%d.%d -> %d.%d.%d.%d", 
        ipv4_addr_to_dec0(ip_hdr->src_addr), 
        ipv4_addr_to_dec1(ip_hdr->src_addr), 
        ipv4_addr_to_dec2(ip_hdr->src_addr), 
        ipv4_addr_to_dec3(ip_hdr->src_addr), 
        ipv4_addr_to_dec0(ip_hdr->dst_addr), 
        ipv4_addr_to_dec1(ip_hdr->dst_addr), 
        ipv4_addr_to_dec2(ip_hdr->dst_addr), 
        ipv4_addr_to_dec3(ip_hdr->dst_addr)
    );
    eh_mdebugln( IP_REASSE, "start offset:%d",ipv4_hdr_offset(ip_hdr));
    eh_mdebugln( IP_REASSE, "end offset:%d",ipv4_hdr_offset(ip_hdr) + ipv4_hdr_body_len(ip_hdr));
    eh_mdebugln( IP_REASSE, "fragment size:%d", ipv4_hdr_body_len(ip_hdr));

    if(ip_fragment_reasse_tab[index] == NULL){
        /* 收到的第一个分片 */
        eh_mdebugln( IP_REASSE, "first fragment!");
        ip_msg = ip_message_rx_new_fragment(buffer->netdev, buffer, ip_hdr, route_type);
        if(eh_ptr_to_error(ip_msg) < 0){
            eh_mdebugln( IP_REASSE, "ip_message_rx_new_fragment error ret = %d!", ret);
            return NULL;
        }
        ip_fragment_reasse_tab[index] = ip_msg;
        return NULL;
    }

    eh_mdebugln( IP_REASSE, "add fragment %d", ip_fragment_reasse_tab[index]->rx_fragment->fragment_cnt);
    
    /* 
     * add 对ip_msg不会做任何更改，而是在ehip_buffer 内部引用计数+1 
     */
    ret = ip_message_rx_add_fragment(ip_fragment_reasse_tab[index], buffer, ip_hdr);
    if(ret < 0){
        ip_message_free(ip_fragment_reasse_tab[index]);
        ip_fragment_reasse_tab[index] = NULL;
        return NULL;
    }

    if(ret == FRAGMENT_REASSE_FINISH){
        struct ip_message *ret_ip_msg = ip_fragment_reasse_tab[index];
        ip_fragment_reasse_tab[index] = NULL;
        return ret_ip_msg;
    }

    return NULL;
}

static void slot_function_ip_reasse_1s_timer_handler(eh_event_t *e, void *slot_param){
    (void)e;
    (void)slot_param;
    for(int i = 0; i < (int)EHIP_IP_MAX_IP_FRAGMENT_BUFFER_NUM; i++){

        if(ip_fragment_reasse_tab[i] == NULL)
            continue;

        if(ip_fragment_reasse_tab[i]->rx_fragment->expires_cd > 0)
            ip_fragment_reasse_tab[i]->rx_fragment->expires_cd--;

        if(ip_fragment_reasse_tab[i]->rx_fragment->expires_cd == 0){
            /* ip分片等待时间超时，释放分片记录 */
            eh_mdebugln( IP_REASSE, "IP fragment timeout, freeing fragment record. [id:%d] [src:%d.%d.%d.%d -> %d.%d.%d.%d]", 
                eh_hton16(ip_fragment_reasse_tab[i]->ip_hdr.id),
                ipv4_addr_to_dec0(ip_fragment_reasse_tab[i]->ip_hdr.src_addr), 
                ipv4_addr_to_dec1(ip_fragment_reasse_tab[i]->ip_hdr.src_addr), 
                ipv4_addr_to_dec2(ip_fragment_reasse_tab[i]->ip_hdr.src_addr), 
                ipv4_addr_to_dec3(ip_fragment_reasse_tab[i]->ip_hdr.src_addr), 
                ipv4_addr_to_dec0(ip_fragment_reasse_tab[i]->ip_hdr.dst_addr), 
                ipv4_addr_to_dec1(ip_fragment_reasse_tab[i]->ip_hdr.dst_addr), 
                ipv4_addr_to_dec2(ip_fragment_reasse_tab[i]->ip_hdr.dst_addr), 
                ipv4_addr_to_dec3(ip_fragment_reasse_tab[i]->ip_hdr.dst_addr)
            );
            ip_message_free(ip_fragment_reasse_tab[i]);
            ip_fragment_reasse_tab[i] = NULL;
        }
    }
}

static EH_DEFINE_SLOT(slot_timer, slot_function_ip_reasse_1s_timer_handler, NULL);

static void ip_handle(struct ehip_buffer* buf){
    struct ip_hdr *ip_hdr = (struct ip_hdr *)ehip_buffer_get_payload_ptr(buf);
    ehip_buffer_size_t buffer_all_len = ehip_buffer_get_payload_size(buf);
    ehip_buffer_size_t ip_msg_len = 0;
    struct ip_message *ip_message;
    struct route_info next_hop;
    enum route_table_type route_type;
    struct ipv4_netdev *ipv4_dev;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
    ehip_buffer_size_t trim_len;

    ipv4_dev = ehip_netdev_trait_ipv4_dev(buf->netdev);
    if(ipv4_dev == NULL)
        goto drop;
    
    if( buf->packet_type == EHIP_PACKET_TYPE_OTHERHOST || 
        (size_t)buffer_all_len < sizeof(struct ip_hdr) ||
        ip_hdr->version != 4 || ip_hdr->ihl < 5 ||
        buffer_all_len < (ehip_buffer_size_t)(ipv4_hdr_len(ip_hdr)) ||
        (ip_msg_len = eh_ntoh16(ip_hdr->tot_len)) < (ehip_buffer_size_t)(ipv4_hdr_len(ip_hdr)) ||
        buffer_all_len < ip_msg_len
    )
        goto drop;
    
    /* 如果是本地回环的包，就无需做检验和 */
    if( buf->packet_type != EHIP_PACKET_TYPE_LOOPBACK && 
        eh_unlikely(ehip_inet_chksum(ip_hdr, ipv4_hdr_len(ip_hdr)) != 0)){
        goto drop;
    }
    /* 修剪尾部多余长度  totlen-iphdr_len */
    trim_len = buffer_all_len - ip_msg_len;
    if(trim_len && ehip_buffer_payload_reduce(buf, trim_len) == NULL)
        goto drop;

    src_addr = ip_hdr->src_addr;
    dst_addr = ip_hdr->dst_addr;

    eh_mdebugln( IP_INPUT, "############### RAW IP PACKET ###############");
    eh_mdebugln( IP_INPUT, "src: %d.%d.%d.%d", 
        ipv4_addr_to_dec0(src_addr), ipv4_addr_to_dec1(src_addr),
        ipv4_addr_to_dec2(src_addr), ipv4_addr_to_dec3(src_addr));
    eh_mdebugln( IP_INPUT, "dst: %d.%d.%d.%d", 
        ipv4_addr_to_dec0(dst_addr), ipv4_addr_to_dec1(dst_addr),
        ipv4_addr_to_dec2(dst_addr), ipv4_addr_to_dec3(dst_addr));
    eh_mdebugln( IP_INPUT, "tos:%02x", ip_hdr->tos);
    eh_mdebugln( IP_INPUT, "iphdr_len:%d", ip_msg_len);
    eh_mdebugln( IP_INPUT, "id:%d", eh_ntoh16(ip_hdr->id));
    eh_mdebugln( IP_INPUT, "frag_off:%04x", eh_ntoh16(ip_hdr->frag_off));
    eh_mdebugln( IP_INPUT, "ttl:%d", ip_hdr->ttl);
    eh_mdebugln( IP_INPUT, "protocol:%02x", ip_hdr->protocol);

    /*
     *  判断本包的目的地址类型
     */
    route_type = ipv4_route_input(src_addr, dst_addr, buf->netdev, &next_hop);
    switch(route_type){
        case ROUTE_TABLE_UNREACHABLE:
            goto drop;
        case ROUTE_TABLE_MULTICAST:
            /* 判断是否为本机的多播报文 */
                goto drop;
        case ROUTE_TABLE_UNICAST:
            if(!ipv4_netdev_flags_is_forward_support(ipv4_dev))
                goto drop;
            /* TODO:  调用转发函数，进行转发*/

            /* fallthrough */
        case ROUTE_TABLE_LOCAL:
            if(!ipv4_netdev_flags_is_forward_support(ipv4_dev))
                goto drop;
        case ROUTE_TABLE_LOCAL_SELF:
        case ROUTE_TABLE_BROADCAST:
            break;
        default:
            goto drop;
    }

    /* 去除头部 */
    ehip_buffer_head_reduce(buf, (ehip_buffer_size_t)(ipv4_hdr_len(ip_hdr)));
    /* 进行分片组合 */
    if(ipv4_hdr_is_fragment(ip_hdr)){
        int i,sort_i;
        ehip_buffer_t *pos_buffer;
        eh_mdebugln( IP_INPUT, "ip fragment !");
        /* buf传入后本函数已经丧失所有权，若执行失败也无需free buf */
        ip_message = ip_reasse(buf, ip_hdr, route_type);
        if(ip_message == NULL)
            return ;
        eh_mdebugln( IP_INPUT, "ip reassemble success!");
        ip_message_rx_fragment_for_each(pos_buffer, i, sort_i, ip_message){
            eh_mdebugln( IP_INPUT, "fragment %d %d", i , ehip_buffer_get_payload_size(pos_buffer));
        }
    }else{
        /* buf传入后本函数已经丧失所有权，若执行失败也无需free buf */
        ip_message = ip_message_rx_new(buf->netdev, buf, ip_hdr, route_type);
        if(eh_ptr_to_error(ip_message) < 0)
            return ;
    }
    /* 到达此行时 ip_hdr 已经不可用，所有权被转移到 ip_message */
    switch (ip_message->ip_hdr.protocol) {
        case IP_PROTO_ICMP:{
            extern void icmp_input(struct ip_message *ip_msg);
            icmp_input(ip_message);
            return ;
        }
        case IP_PROTO_IGMP:
            ip_message_free(ip_message);
            break;
        case IP_PROTO_UDP:
        case IP_PROTO_UDPLITE:{
            extern void udp_input(struct ip_message *ip_msg);
            udp_input(ip_message);
            return ;
        }
        case IP_PROTO_TCP:
            ip_message_free(ip_message);
            break;
    }
    return ;
drop:
    ehip_buffer_free(buf);
    return ;
}

static struct ehip_protocol_handle ip_protocol_handle = {
    .ptype = EHIP_PTYPE_ETHERNET_IP,
    .handle = ip_handle,
    .node = EH_LIST_HEAD_INIT(ip_protocol_handle.node),
};


static int __init ip_protocol_parser_init(void){
    eh_signal_slot_connect(&signal_ehip_timer_1s, &slot_timer);
    return ehip_protocol_handle_register(&ip_protocol_handle);
}

static void __exit ip_protocol_parser_exit(void){
    ip_fragment_clean();
    eh_signal_slot_disconnect(&slot_timer);
    ehip_protocol_handle_unregister(&ip_protocol_handle);
}

ehip_protocol_module_export(ip_protocol_parser_init, ip_protocol_parser_exit);