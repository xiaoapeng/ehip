/**
 * @file udp.c
 * @brief 
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-03-09
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */


#include <eh.h>
#include <eh_signal.h>
#include <eh_platform.h>
#include <eh_event.h>
#include <eh_timer.h>
#include <eh_error.h>
#include <eh_types.h>
#include <eh_mem.h>
#include <eh_mem_pool.h>
#include <eh_list.h>
#include <eh_swab.h>
#include <eh_hashtbl.h>
#include <eh_debug.h>
#include <ehip_buffer.h>
#include <ehip_error.h>
#include <ehip_netdev_trait.h>
#include <ehip_module.h>
#include <ehip_netdev.h>
#include <ehip_chksum.h>
#include <ehip-ipv4/arp.h>
#include <ehip-ipv4/udp.h>
#include <ehip-ipv4/ip_message.h>
#include <ehip-ipv4/ip.h>
#include <ehip-ipv4/route.h>
#include <ehip-ipv4/ip_tx.h>
#include <ehip-ipv4/_pseudo_header.h>
#include <ehip-mac/loopback.h>


#define UDP_SENDER_REFRESH_TIMEOUT   3000ULL

#define UDP_PCB_PRIVATE_FLAGS_ANY           0x00000001U
#define UDP_PCB_PRIVATE_FLAGS_BIT_WIDTH     4

#define udp_pcb_is_any(pcb)         ((pcb)->flags & UDP_PCB_PRIVATE_FLAGS_ANY)
#define udp_pcb_is_nochksum(pcb)    ((pcb)->flags & ((UDP_PCB_FLAGS_NOCHKSUM) << UDP_PCB_PRIVATE_FLAGS_BIT_WIDTH))
#define udp_pcb_is_udplite(pcb)     ((pcb)->flags & ((UDP_PCB_FLAGS_UDPLITE) << UDP_PCB_PRIVATE_FLAGS_BIT_WIDTH))

struct udp_opt{
    void (*recv_callback)(udp_pcb_t pcb, ipv4_addr_t addr, uint16_be_t port, struct ip_message *udp_rx_meg);
    void (*error_callback)(udp_pcb_t pcb, ipv4_addr_t addr, uint16_be_t port, int err);
};

struct udp_pcb{
    void                            *userdata;
    uint32_t                        flags;
    struct eh_hashtbl_node          *node;
    struct udp_opt                  opt;
};

struct udp_pcb_restrict{
    struct udp_pcb                  pcb;
    struct ehip_netdev              *netdev;
    ipv4_addr_t                     src_addr;
};

eh_static_assert(eh_offsetof(struct udp_pcb_restrict, pcb) == 0, "pcb must be the first member of struct");

struct udp_key{
    uint16_be_t              src_port;
};

struct udp_value{
    udp_pcb_t                 pcb;
};

static eh_hashtbl_t         udp_hash_tbl;

static int udp_pcb_base_init(struct udp_pcb *pcb, uint16_be_t bind_port){
    struct eh_hashtbl_node          *node;
    struct udp_key key;
    struct udp_value *value;
    int ret;
    key.src_port = bind_port;
    node = eh_hashtbl_node_new(udp_hash_tbl, &key, (eh_hashtbl_kv_len_t)sizeof(struct udp_key), 
        (eh_hashtbl_kv_len_t)sizeof(struct udp_value));
    if(node == NULL)
        return EH_RET_MALLOC_ERROR;
    value = eh_hashtbl_node_value(node);
    value->pcb = (udp_pcb_t)pcb;
    ret = eh_hashtbl_insert(udp_hash_tbl, node);
    if(ret < 0)
        goto eh_hashtbl_insert_error;
    pcb->node = node;
    return 0;
    
eh_hashtbl_insert_error:
    eh_hashtbl_node_delete(udp_hash_tbl, node);
    return ret;
}

static void udp_pcb_base_deinit(struct udp_pcb * pcb){
    if(pcb->node == NULL)
        return;
    
    eh_hashtbl_node_delete(udp_hash_tbl, pcb->node);
    pcb->node = NULL;
}

static int udp_sender_force_refresh(struct udp_sender *sender){
    struct route_info route;
    ipv4_addr_t best_src_addr;
    enum route_table_type route_type;
    struct udp_pcb *base_pcb = (struct udp_pcb *)sender->pcb;
    memset(&route, 0, sizeof(struct route_info));
    
    sender->last_check_time = eh_get_clock_monotonic_time();
    sender->route_type = ROUTE_TABLE_UNREACHABLE;

    if(udp_pcb_is_any(base_pcb)){
        /* 检查路由是否可达 */
        route_type = ipv4_route_lookup(sender->dst_addr, NULL, &route, &best_src_addr);
        if(route_type == ROUTE_TABLE_UNREACHABLE)
            return EHIP_RET_UNREACHABLE;
        sender->src_addr = best_src_addr;
        sender->netdev = route.netdev;
    }else{
        struct udp_pcb_restrict *restrict_pcb = (struct udp_pcb_restrict *)sender->pcb;
        struct ipv4_netdev *ipv4_netdev;

        ipv4_netdev = ehip_netdev_trait_ipv4_dev(restrict_pcb->netdev);
        /* 检查IP是否有效 */
        if( restrict_pcb->src_addr != IPV4_ADDR_DHCP_CLIENT && 
            ipv4_netdev_get_ipv4_addr_idx(ipv4_netdev, restrict_pcb->src_addr) < 0 ){
            return EHIP_RET_ADDR_NOT_EXISTS;
        }

        /* 检查路由是否可达 */
        route_type = ipv4_route_lookup(sender->dst_addr, restrict_pcb->netdev, &route, NULL);
        if(route_type == ROUTE_TABLE_UNREACHABLE)
            return EHIP_RET_UNREACHABLE;
        sender->src_addr = restrict_pcb->src_addr;
    }

    if( (route_type == ROUTE_TABLE_LOCAL || route_type == ROUTE_TABLE_LOCAL_SELF ) && 
        !ipv4_netdev_flags_is_loopback_support(ehip_netdev_trait_ipv4_dev(sender->netdev))){
        return EHIP_RET_UNREACHABLE;
    }
    
    if(!(ehip_netdev_flags_get(sender->netdev) & EHIP_NETDEV_STATUS_UP))
        return EHIP_RET_UNREACHABLE;

    sender->gw_addr = route.gateway;
    sender->route_type = route_type;
    return 0;
}

static int udp_sender_refresh(struct udp_sender *sender){
    if(sender->route_type == ROUTE_TABLE_UNREACHABLE || eh_diff_time(eh_get_clock_monotonic_time(), sender->last_check_time) > (eh_sclock_t)eh_msec_to_clock(UDP_SENDER_REFRESH_TIMEOUT)){
        return udp_sender_force_refresh(sender);
    }
    return 0;
}


void udp_error_input(ipv4_addr_t err_sender, struct ip_hdr *ip_hdr, const uint8_t *payload, int payload_len, int error){
    (void)err_sender;
    const struct udp_hdr *udp_hdr;
    struct udp_key key;
    struct eh_hashtbl_node *node_pos, *node_tmp_n;
    struct udp_value *value;
    struct eh_list_head *node_head;
    struct udp_pcb *base_pcb;

    if(payload_len < (int)sizeof(struct udp_hdr))
        return ;
    udp_hdr = (const struct udp_hdr *)payload;
    /* 通过HASH找到udp_pcb,如果没有任何的udp_pcb则说明该端口根本无人绑定，那直接丢弃 */
    key.src_port = udp_hdr->dest;
    eh_hashtbl_for_each_with_key_safe(udp_hash_tbl, &key, 
        sizeof(struct udp_key), node_pos, node_tmp_n, node_head){
        value = eh_hashtbl_node_value(node_pos);
        base_pcb = (struct udp_pcb *)value->pcb;
        if(base_pcb->opt.error_callback){
            base_pcb->opt.error_callback((udp_pcb_t)base_pcb, ip_hdr->dst_addr, udp_hdr->dest, error);
        }
    }
}

void udp_input(struct ip_message *ip_msg){
    int ret;
    struct udp_hdr *udp_hdr;
    struct udp_hdr udp_hdr_tmp;
    struct pseudo_header pseudo_header;
    uint16_t udp_checksum = 0;
    uint16_t udp_data_len;
    ehip_buffer_size_t trim_len;
    struct udp_key key;
    struct eh_hashtbl_node *node_pos, *node_tmp_n;
    struct udp_value *value;
    struct eh_list_head *node_head;
    struct udp_pcb *base_pcb;
    struct udp_pcb_restrict *restrict_pcb;
    struct ip_message *ip_msg_tmp;
    

    ret = ip_message_rx_read(ip_msg, (uint8_t**)&udp_hdr, sizeof(struct udp_hdr), (uint8_t*)&udp_hdr_tmp);
    if(ret != sizeof(struct udp_hdr)){
        eh_msysfl(UDP_INPUT, "udp_hdr read error %d", ret);
        goto drop;
    }

    udp_data_len = eh_ntoh16(udp_hdr->len) - (uint16_t)sizeof(struct udp_hdr);
    eh_mdebugfl(UDP_INPUT, "############### INPUT RAW UDP PACKET ###############");
    eh_mdebugfl(UDP_INPUT, IPV4_FORMATIO":%d->"IPV4_FORMATIO":%d len:%d",
        ipv4_formatio(ip_msg->ip_hdr.src_addr), eh_ntoh16(udp_hdr->source),
        ipv4_formatio(ip_msg->ip_hdr.dst_addr), eh_ntoh16(udp_hdr->dest), udp_data_len);
    eh_mdebugfl(UDP_INPUT, "check: %#hx", udp_hdr->check);
    if(!ip_message_flag_is_fragment(ip_msg)){
        eh_mdebugfl(UDP_INPUT,"payload %.*hhq", ehip_buffer_get_payload_size(ip_msg->buffer), 
            (uint8_t *)ehip_buffer_get_payload_ptr(ip_msg->buffer));
    }

    if( ip_message_rx_data_size(ip_msg) < udp_data_len ){
        eh_mwarnfl(UDP_INPUT, "ip_message_rx_data_size:%d udp_data_len:%d", 
            ip_message_rx_data_size(ip_msg), udp_data_len);
        goto drop;
    }

    /* 通过HASH找到udp_pcb,如果没有任何的udp_pcb则说明该端口根本无人绑定，那直接丢弃 */
    key.src_port = udp_hdr->dest;
    ret = eh_hashtbl_find(udp_hash_tbl, &key, sizeof(struct udp_key), NULL);
    if(ret < 0){
        eh_mdebugfl(UDP_INPUT, "port:%d no bind.", eh_ntoh16(udp_hdr->dest));
        goto drop;
    }

    if(ip_msg->ip_hdr.protocol == IP_PROTO_UDP){

        trim_len = (ehip_buffer_size_t)ip_message_rx_data_size(ip_msg) - udp_data_len;
        if(trim_len && ip_message_rx_data_tail_trim(ip_msg, trim_len) < 0){
            /* 正常来说不可能失败 */
            eh_merrfl(UDP_INPUT, "udp trim fail");
            goto drop;
        }
        if(udp_hdr->check){
            /* 计算伪首部校验和 */
            pseudo_header.src_addr = ip_msg->ip_hdr.src_addr;
            pseudo_header.dst_addr = ip_msg->ip_hdr.dst_addr;
            pseudo_header.zero = 0;
            pseudo_header.proto = IP_PROTO_UDP;
            pseudo_header.len = udp_hdr->len;
            udp_checksum = ehip_inet_chksum_accumulated(udp_checksum, &pseudo_header, sizeof(struct pseudo_header));
            udp_checksum = ehip_inet_chksum_accumulated(udp_checksum, udp_hdr, sizeof(struct udp_hdr));
            if(ip_message_flag_is_fragment(ip_msg)){
                ehip_buffer_t *pos_buffer;
                int tmp_i, tmp_sort_i;
                uint16_t single_chksum_len;
                /* 分片数据校验 */
                ip_message_rx_fragment_for_each(pos_buffer, tmp_i, tmp_sort_i, ip_msg){
                    single_chksum_len = ehip_buffer_get_payload_size(pos_buffer);
                    udp_checksum = ehip_inet_chksum_accumulated(udp_checksum, 
                        ehip_buffer_get_payload_ptr(pos_buffer), single_chksum_len);
                }
            }else{
                udp_checksum = ehip_inet_chksum_accumulated(udp_checksum, 
                    ehip_buffer_get_payload_ptr(ip_msg->buffer), ehip_buffer_get_payload_size(ip_msg->buffer));
            }
            if(udp_checksum != 0x0 && udp_checksum != 0xFFFF){
                eh_mwarnfl(UDP_INPUT, "udp_hdr checksum error %#hx", udp_hdr->check);
                goto drop;
            }

        }
    }else{
        /* IP_PROTO_UDPLITE */
        /* TODO */
        goto drop;
    }

    eh_hashtbl_for_each_with_key_safe(udp_hash_tbl, &key, 
        sizeof(struct udp_key), node_pos, node_tmp_n, node_head){
        value = eh_hashtbl_node_value(node_pos);
        base_pcb = (struct udp_pcb *)value->pcb;
        if(!udp_pcb_is_any(base_pcb)){
            restrict_pcb = (struct udp_pcb_restrict *)base_pcb;
            if( restrict_pcb->src_addr != ip_msg->ip_hdr.dst_addr ||
                restrict_pcb->netdev != ip_msg->tx_init_netdev)
                continue;
        }

        if(udp_pcb_is_udplite(base_pcb) && ip_msg->ip_hdr.protocol == IP_PROTO_UDP){
            eh_mdebugfl(UDP_INPUT, "udp_pcb_is_udplite");
            continue;
        }

        /* 找到udp_pcb */
        if(base_pcb->opt.recv_callback){
            ip_msg_tmp = ip_message_rx_ref_dup(ip_msg);
            if(ip_msg_tmp == NULL){
                eh_mwarnfl(UDP_INPUT, "ip_message_rx_ref_dup fail");
                continue;
            }
            base_pcb->opt.recv_callback((udp_pcb_t)base_pcb, ip_msg_tmp->ip_hdr.src_addr, udp_hdr->source, ip_msg_tmp);
            ip_message_free(ip_msg_tmp);
        }

    }
drop:
    ip_message_free(ip_msg);
    return ;
}



udp_pcb_t ehip_udp_new(ipv4_addr_t bind_addr, uint16_be_t bind_port , ehip_netdev_t *netdev){
    struct udp_pcb_restrict *pcb;
    struct ipv4_netdev* ipv4_netdev;
    int ret;
    if(!netdev || (ipv4_netdev = ehip_netdev_trait_ipv4_dev(netdev)) == NULL || ipv4_is_global_bcast(bind_addr) )
        return eh_error_to_ptr(EH_RET_INVALID_PARAM);

    pcb = (struct udp_pcb_restrict*)eh_malloc(sizeof(struct udp_pcb_restrict));
    if(pcb == NULL)
        return eh_error_to_ptr(EH_RET_MALLOC_ERROR);
    memset(pcb, 0, sizeof(struct udp_pcb_restrict));
    pcb->src_addr = bind_addr;
    pcb->netdev = netdev;
    ret = udp_pcb_base_init((struct udp_pcb*)pcb, bind_port);
    if(ret < 0){
        eh_free(pcb);
        return eh_error_to_ptr(ret);
    }
    return (udp_pcb_t)pcb;
}

udp_pcb_t ehip_udp_any_new(uint16_be_t bind_port){
    struct udp_pcb *pcb;
    int ret;

    pcb = (struct udp_pcb*)eh_malloc(sizeof(struct udp_pcb));
    if(pcb == NULL)
        return eh_error_to_ptr(EH_RET_MALLOC_ERROR);
    memset(pcb, 0, sizeof(struct udp_pcb));
    pcb->flags = UDP_PCB_PRIVATE_FLAGS_ANY;
    ret = udp_pcb_base_init((struct udp_pcb*)pcb, bind_port);
    if(ret < 0){
        eh_free(pcb);
        return eh_error_to_ptr(ret);
    }
    return (udp_pcb_t)pcb;
}

void ehip_udp_delete(udp_pcb_t pcb){
    udp_pcb_base_deinit((struct udp_pcb *)pcb);
    eh_free(pcb);
    return ;
}

void      ehip_udp_set_flags(udp_pcb_t pcb, uint32_t flags){
    ((struct udp_pcb *)pcb)->flags |= flags << UDP_PCB_PRIVATE_FLAGS_BIT_WIDTH;
}

void ehip_udp_set_userdata(udp_pcb_t _pcb, void *userdata){
    struct udp_pcb *pcb = (struct udp_pcb *)_pcb;
    pcb->userdata = userdata;
}

void* ehip_udp_get_userdata(udp_pcb_t pcb){
    return ((struct udp_pcb *)pcb)->userdata;
}

void ehip_udp_set_recv_callback(udp_pcb_t _pcb, 
        void (*recv_callback)(udp_pcb_t pcb, ipv4_addr_t addr, uint16_be_t port, struct ip_message *udp_rx_meg)){
    struct udp_pcb *pcb = (struct udp_pcb *)_pcb;
    pcb->opt.recv_callback = recv_callback;
}

void ehip_udp_set_error_callback(udp_pcb_t _pcb, 
        void (*error_callback)(udp_pcb_t pcb, ipv4_addr_t addr, uint16_be_t port, int err)){
    struct udp_pcb *pcb = (struct udp_pcb *)_pcb;
    pcb->opt.error_callback = error_callback;
}


int ehip_udp_sender_init_ready(udp_pcb_t _pcb, struct udp_sender *sender, 
    ipv4_addr_t dst_addr, uint16_be_t dst_port){
    struct udp_pcb *pcb = (struct udp_pcb *)_pcb;
    sender->pcb = _pcb;
    sender->arp_idx_cache = -1;
    sender->dst_addr = dst_addr;
    sender->dst_port = dst_port;
    sender->src_port = ((const struct udp_key*)eh_hashtbl_node_const_key(pcb->node))->src_port;
    sender->ip_msg = NULL;
    return udp_sender_force_refresh(sender);
}


void ehip_udp_sender_buffer_clean(struct udp_sender *sender){
    if(sender->ip_msg){
        ip_message_free(sender->ip_msg);
        sender->ip_msg = NULL;
    }
}

int ehip_udp_sender_add_buffer(struct udp_sender *sender, 
    ehip_buffer_t** out_buffer, ehip_buffer_size_t *out_buffer_capacity_size){
    struct ip_message* tx_msg = NULL;
    struct udp_pcb *pcb = (struct udp_pcb *)sender->pcb;

    if(sender->route_type == ROUTE_TABLE_UNREACHABLE)
        return EHIP_RET_UNREACHABLE;

    if(!sender->ip_msg){
        uint8_t ttl;
        if(sender->route_type == ROUTE_TABLE_MULTICAST && ipv4_is_local_multicast(sender->dst_addr)){
            ttl = 1;
        }else{
            ttl = EHIP_IP_DEFAULT_TTL;
        }

        sender->ip_msg = ip_message_tx_new(sender->netdev, ipv4_make_tos(0, 0), 
            ttl, udp_pcb_is_udplite(pcb)? IP_PROTO_UDPLITE : IP_PROTO_UDP, sender->src_addr, 
            sender->dst_addr, NULL, 0, sizeof(struct udp_hdr), sender->route_type);
        if(sender->ip_msg == NULL)
            return EH_RET_MEM_POOL_EMPTY;
    }
    tx_msg = sender->ip_msg;

    return ip_message_tx_add_buffer(tx_msg, out_buffer, out_buffer_capacity_size);
}


int ehip_udp_send(udp_pcb_t _pcb, struct udp_sender *sender){
    struct udp_pcb *pcb = (struct udp_pcb *)_pcb;
    struct udp_hdr udp_hdr;
    struct pseudo_header pseudo_header;
    uint16_le_t udp_len = 0;
    uint16_le_t udp_fragment_len = 0;
    uint16_t udp_checksum = 0;
    ehip_buffer_t *pos_buffer;
    bool is_no_chksum = udp_pcb_is_nochksum(pcb);
    bool is_udplite = udp_pcb_is_udplite(pcb);
    int tmp_i;
    int ret = 0;

    if(sender->ip_msg == NULL)
        return EH_RET_INVALID_PARAM;
    
    ret = udp_sender_refresh(sender);
    if(ret < 0)
        goto exit;

    if(sender->route_type == ROUTE_TABLE_UNREACHABLE){
        goto exit;
    }

    udp_hdr.source = sender->src_port;
    udp_hdr.dest = sender->dst_port;
    
    pseudo_header.src_addr = sender->src_addr;
    pseudo_header.dst_addr = sender->dst_addr;
    pseudo_header.zero = 0;

    if(is_udplite){
        /* udp lite TODO */
        ret = EH_RET_NOT_SUPPORTED;
        goto exit;
    }else{
        if(ip_message_flag_is_fragment(sender->ip_msg)){
            ip_message_tx_fragment_for_each(pos_buffer, tmp_i, sender->ip_msg){
                udp_fragment_len = ehip_buffer_get_payload_size(pos_buffer);
                udp_len += udp_fragment_len;
                if(!is_no_chksum)
                    udp_checksum = ehip_inet_chksum_accumulated(udp_checksum, ehip_buffer_get_payload_ptr(pos_buffer), udp_fragment_len);
            }
        }else{
            udp_len = ehip_buffer_get_payload_size(sender->ip_msg->buffer);
            if(!is_no_chksum)
                udp_checksum = ehip_inet_chksum_accumulated(udp_checksum, ehip_buffer_get_payload_ptr(sender->ip_msg->buffer), udp_len);
        }

        udp_hdr.len = eh_hton16(udp_len + (uint16_t)sizeof(struct udp_hdr)) ;
        udp_hdr.check = 0;

        pseudo_header.proto = IP_PROTO_UDP;
        pseudo_header.len = udp_hdr.len;

        if(!is_no_chksum){
            udp_checksum = ehip_inet_chksum_accumulated(udp_checksum, (uint16_t *)&pseudo_header, sizeof(struct pseudo_header));
            udp_hdr.check = ehip_inet_chksum_accumulated(udp_checksum, (uint16_t *)&udp_hdr, sizeof(struct udp_hdr));
            udp_hdr.check = udp_hdr.check == 0 ? 0xffff : udp_hdr.check;
        }
    }
    
    if(sender->route_type == ROUTE_TABLE_MULTICAST && sender->gw_addr == IPV4_ADDR_ANY){
        /* 处理本地多播无需ARP */
        /* TODO */
        goto exit;
    }
    
    ret = ip_message_tx_ready(sender->ip_msg, (const uint8_t *)&udp_hdr);
    if(ret < 0)
        goto exit;

    ret = ip_tx(sender->netdev, sender->ip_msg, &sender->arp_idx_cache, sender->gw_addr);
    sender->ip_msg = NULL;
    return ret;
exit:
    ehip_udp_sender_buffer_clean(sender);
    return ret;
}


static int udp_init(void){
    udp_hash_tbl = eh_hashtbl_create(EH_HASHTBL_DEFAULT_LOADFACTOR);
    if(eh_ptr_to_error(udp_hash_tbl) < 0)
        return eh_ptr_to_error(udp_hash_tbl);
    return 0;
}

static void udp_exit(void){
    eh_hashtbl_destroy(udp_hash_tbl);
}


ehip_protocol_module_export(udp_init, udp_exit);

