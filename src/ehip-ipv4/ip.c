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


#if EHIP_IP_DEBUG
#define ip_debugfl(...) eh_debugfl(__VA_ARGS__)
#else
#define ip_debugfl(...)
#endif

struct ip_message *ip_fragment_reasse_tab[EHIP_IP_MAX_IP_FRAGMENT_BUFFER_NUM];

int ip_fragment_find(const struct ip_message *ip_msg_ref){
    uint8_t old_expires_cd = 0xFF;
    int old_index = -1;             /* 最旧的分片记录号 */
    int null_index = -1;            /* 空闲的分片记录号 */
    

    for(int i = 0; i < (int)EHIP_IP_MAX_IP_FRAGMENT_BUFFER_NUM; i++){
        if(ip_fragment_reasse_tab[i] == NULL){
            null_index = i;
            continue;
        }
        if( ip_fragment_reasse_tab[i]->ip_hdr->id == ip_msg_ref->ip_hdr->id  && 
            ip_fragment_reasse_tab[i]->ip_hdr->src_addr == ip_msg_ref->ip_hdr->src_addr &&
            ip_fragment_reasse_tab[i]->ip_hdr->dst_addr == ip_msg_ref->ip_hdr->dst_addr &&
            ip_fragment_reasse_tab[i]->ip_hdr->protocol == ip_msg_ref->ip_hdr->protocol
        ){
            return i;
        }
        if(old_index == -1 || ip_fragment_reasse_tab[i]->expires_cd < old_expires_cd){
            old_expires_cd = ip_fragment_reasse_tab[i]->expires_cd;
            old_index = i;
        }
    }
    if(null_index) return null_index;
    if(old_index == -1)
        return -1;
    /* 释放空闲的分片记录 */
    ip_message_free_and_buffer_clean(ip_fragment_reasse_tab[old_index]);
    ip_fragment_reasse_tab[old_index] = NULL;
    return old_index;
}

/**
 * @brief                   组装分片的IP数据包
 * @param  ip_msg           My Param doc
 * @return struct ip_message* 
 */
static struct ip_message * ip_reasse(struct ip_message *ip_msg){
    int index;
    int ret;
    if((index = ip_fragment_find(ip_msg)) < 0){
        eh_errfl("IP fragment buffer is full, drop fragment.");
        ip_message_free_and_buffer_clean(ip_msg);
        return NULL;
    }
    ip_debugfl("ip fragment index:%d", index);
    ip_debugfl("id:%d", eh_hton16(ip_msg->ip_hdr->id));
    ip_debugfl("src:%d.%d.%d.%d -> %d.%d.%d.%d", 
        ipv4_addr_to_dec0(ip_msg->ip_hdr->src_addr), 
        ipv4_addr_to_dec1(ip_msg->ip_hdr->src_addr), 
        ipv4_addr_to_dec2(ip_msg->ip_hdr->src_addr), 
        ipv4_addr_to_dec3(ip_msg->ip_hdr->src_addr), 
        ipv4_addr_to_dec0(ip_msg->ip_hdr->dst_addr), 
        ipv4_addr_to_dec1(ip_msg->ip_hdr->dst_addr), 
        ipv4_addr_to_dec2(ip_msg->ip_hdr->dst_addr), 
        ipv4_addr_to_dec3(ip_msg->ip_hdr->dst_addr)
    );
    ip_debugfl("start offset:%d",ipv4_hdr_offset(ip_msg->ip_hdr));
    ip_debugfl("end offset:%d",ipv4_hdr_offset(ip_msg->ip_hdr) + ipv4_hdr_body_len(ip_msg->ip_hdr));
    ip_debugfl("fragment size:%d", ipv4_hdr_body_len(ip_msg->ip_hdr));
    if(ip_fragment_reasse_tab[index] == NULL){
        /* 收到的第一个分片 */
        ip_debugfl("first fragment!");
        ret = ip_message_convert_to_fragment(ip_msg);
        if(ret < 0){
            ip_message_free_and_buffer_clean(ip_msg);
        }else{
            ip_fragment_reasse_tab[index] = ip_msg;
        }
        return NULL;
    }
    ip_debugfl("add fragment %d", ip_fragment_reasse_tab[index]->fragment_num);
    ret = ip_message_add_fragment(ip_fragment_reasse_tab[index], ip_msg);
    ip_message_free_and_buffer_clean(ip_msg);
    if(ret < 0){
        ip_message_free_and_buffer_clean(ip_fragment_reasse_tab[index]);
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

        if(ip_fragment_reasse_tab[i]->expires_cd > 0)
            ip_fragment_reasse_tab[i]->expires_cd--;

        if(ip_fragment_reasse_tab[i]->expires_cd == 0){
            /* ip分片等待时间超时，释放分片记录 */
            ip_debugfl("IP fragment timeout, freeing fragment record. [id:%d] [src:%d.%d.%d.%d -> %d.%d.%d.%d]", 
                eh_hton16(ip_fragment_reasse_tab[i]->ip_hdr->id),
                ipv4_addr_to_dec0(ip_fragment_reasse_tab[i]->ip_hdr->src_addr), 
                ipv4_addr_to_dec1(ip_fragment_reasse_tab[i]->ip_hdr->src_addr), 
                ipv4_addr_to_dec2(ip_fragment_reasse_tab[i]->ip_hdr->src_addr), 
                ipv4_addr_to_dec3(ip_fragment_reasse_tab[i]->ip_hdr->src_addr), 
                ipv4_addr_to_dec0(ip_fragment_reasse_tab[i]->ip_hdr->dst_addr), 
                ipv4_addr_to_dec1(ip_fragment_reasse_tab[i]->ip_hdr->dst_addr), 
                ipv4_addr_to_dec2(ip_fragment_reasse_tab[i]->ip_hdr->dst_addr), 
                ipv4_addr_to_dec3(ip_fragment_reasse_tab[i]->ip_hdr->dst_addr)
            );
            ip_message_free_and_buffer_clean(ip_fragment_reasse_tab[i]);
            ip_fragment_reasse_tab[i] = NULL;
        }
    }
}

static EH_DEFINE_SLOT(slot_timer, slot_function_ip_reasse_1s_timer_handler, NULL);

static void ip_handle(struct ehip_buffer* buf){
    struct ip_hdr *ip_hdr = (struct ip_hdr *)ehip_buffer_get_payload_ptr(buf);
    ehip_buffer_size_t totlen = ehip_buffer_get_buffer_size(buf);
    ehip_buffer_size_t iphdr_len = 0;
    struct ip_message *ip_message;
    struct route_info next_hop;
    enum route_table_type route_type;
    struct ipv4_netdev *ipv4_dev;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;

    
    ipv4_dev = ehip_netdev_trait_ipv4_dev(buf->netdev);
    if(ipv4_dev == NULL)
        goto drop;
    
    if( buf->packet_type == EHIP_PACKET_TYPE_OTHERHOST || 
        (size_t)totlen < sizeof(struct ip_hdr) ||
        ip_hdr->version != 4 || ip_hdr->ihl < 5 ||
        ehip_buffer_head_reduce(buf, (ehip_buffer_size_t)(ip_hdr->ihl << 2)) == NULL ||
        (iphdr_len = eh_ntoh16(ip_hdr->tot_len)) < (ehip_buffer_size_t)(ip_hdr->ihl << 2) ||
        totlen < iphdr_len
    )
        goto drop;

    if(eh_unlikely(ehip_inet_chksum(ip_hdr, ip_hdr->ihl << 2) != 0))
        goto drop;
    ip_message = ip_message_new();
    if(ip_message == NULL)
        goto drop;
    ip_message->ip_hdr = ip_hdr;
    ip_message->buffer = buf;
    src_addr = ip_hdr->src_addr;
    dst_addr = ip_hdr->dst_addr;

    ip_debugfl("############### RAW IP PACKET ###############");
    ip_debugfl("src: %d.%d.%d.%d", 
        ipv4_addr_to_dec0(src_addr), ipv4_addr_to_dec1(src_addr),
        ipv4_addr_to_dec2(src_addr), ipv4_addr_to_dec3(src_addr));
    ip_debugfl("dst: %d.%d.%d.%d", 
        ipv4_addr_to_dec0(dst_addr), ipv4_addr_to_dec1(dst_addr),
        ipv4_addr_to_dec2(dst_addr), ipv4_addr_to_dec3(dst_addr));
    ip_debugfl("tos:%02x", ip_hdr->tos);
    ip_debugfl("iphdr_len:%d", iphdr_len);
    ip_debugfl("id:%d", eh_ntoh16(ip_hdr->id));
    ip_debugfl("frag_off:%04x", eh_ntoh16(ip_hdr->frag_off));
    ip_debugfl("ttl:%d", ip_hdr->ttl);
    ip_debugfl("protocol:%02x", ip_hdr->protocol);

    /*
     *  判断本包的目的地址类型
     */
    route_type = ipv4_route_input(src_addr, dst_addr, buf->netdev, &next_hop);
    switch(route_type){
        case ROUTE_TABLE_UNREACHABLE:
            goto ip_message_drop;
        case ROUTE_TABLE_MULTICAST:
            /* 判断是否为本机的多播报文 */
                goto ip_message_drop;
        case ROUTE_TABLE_BROADCAST:
            break;
        case ROUTE_TABLE_ANYCAST:
        case ROUTE_TABLE_UNICAST:
            if(!ipv4_netdev_flags_is_forward_support(ipv4_dev))
                goto ip_message_drop;
            /* TODO:  调用转发函数，进行转发*/

            /* fallthrough */
        case ROUTE_TABLE_LOCAL:
            if(!ipv4_netdev_flags_is_forward_support(ipv4_dev))
                goto ip_message_drop;
        case ROUTE_TABLE_LOCAL_SELF:
            break;
    }
    
    /* 进行分片组合 */
    if(ipv4_hdr_is_fragment(ip_hdr)){
        int i,sort_i;
        ehip_buffer_t *pos_buffer;
        ip_debugfl("ip fragment !");
        ip_message = ip_reasse(ip_message);
        if(ip_message == NULL)
            return ;
        ip_debugfl("ip reassemble success!");
        ip_message_fragment_for_each(pos_buffer, i, sort_i, ip_message){
            // ip_debugfl("fragment %d %d : |%.*hhq|", i ,
            //     ehip_buffer_get_payload_size(pos_buffer),
            //     ehip_buffer_get_payload_size(pos_buffer),
            //     ehip_buffer_get_payload_ptr(pos_buffer));
            ip_debugfl("fragment %d %d", i , ehip_buffer_get_payload_size(pos_buffer));
        }
    }

ip_message_drop:
    /* ip_message_free中会自动释放 ehip_buffer */
    ip_message_free_and_buffer_clean(ip_message);
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
    eh_signal_slot_disconnect(&slot_timer);
    ehip_protocol_handle_unregister(&ip_protocol_handle);
}

ehip_protocol_module_export(ip_protocol_parser_init, ip_protocol_parser_exit);