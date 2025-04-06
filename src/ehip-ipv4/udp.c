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
    eh_mem_pool_t                   action_pool;
};

struct udp_pcb_restrict{
    struct udp_pcb                  pcb;
    struct ehip_netdev              *netdev;
    ipv4_addr_t                     src_ip;
};

eh_static_assert(eh_offsetof(struct udp_pcb_restrict, pcb) == 0, "pcb must be the first member of struct");

struct udp_key{
    uint16_be_t              src_port;
};

struct udp_value{
    udp_pcb_t                 pcb;
};

struct arp_changed_action{
    struct arp_changed_callback action;
    struct ip_message           *ip_msg;
    struct udp_pcb              *pcb;
    struct udp_hdr              udp_hdr;
};

static eh_hashtbl_t         udp_hash_tbl;
static eh_sclock_t          udp_sender_refresh_timeout; 

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
    pcb->action_pool = eh_mem_pool_create(EHIP_POOL_BASE_ALIGN, sizeof(struct arp_changed_action), EHIP_UDP_ARP_CHANGED_ACTION_CNT);
    if((ret = eh_ptr_to_error(pcb->action_pool)) < 0)
        goto eh_mem_pool_create_error;
    return 0;
    
eh_mem_pool_create_error:
eh_hashtbl_insert_error:
    eh_hashtbl_node_delete(udp_hash_tbl, node);
    return ret;
}

static void udp_pcb_base_deinit(struct udp_pcb * pcb){
    int i;
    struct arp_changed_action *action;
    if(pcb->node == NULL)
        return;
    
    eh_mem_pool_for_each(i, pcb->action_pool, action){
        if(eh_mem_pool_idx_is_used(pcb->action_pool, i)){
            /* 如果在使用中，就说明被注册进了arp_changed_callback_register，此时需要取消注册，并释放ip_message */
            arp_changed_callback_unregister(&action->action);
            ip_message_free(action->ip_msg);
        }
    }
    eh_mem_pool_destroy(pcb->action_pool);
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
    sender->netdev = NULL;
    sender->src_addr = IPV4_ADDR_ANY;
    sender->gw_addr = IPV4_ADDR_ANY;

    if(udp_pcb_is_any(base_pcb)){
        /* 检查路由是否可达 */
        route_type = ipv4_route_lookup(sender->dts_addr, NULL, &route, &best_src_addr);
        if(route_type == ROUTE_TABLE_UNREACHABLE)
            return EHIP_RET_UNREACHABLE;
        sender->src_addr = best_src_addr;
    }else{
        int ip_idx = -1;
        struct udp_pcb_restrict *restrict_pcb = (struct udp_pcb_restrict *)sender->pcb;
        struct ipv4_netdev *ipv4_netdev;

        ipv4_netdev = ehip_netdev_trait_ipv4_dev(restrict_pcb->netdev);
        /* 检查IP是否有效 */
        if( restrict_pcb->src_ip != IPV4_ADDR_DHCP_CLIENT && 
            (ip_idx = ipv4_netdev_get_ipv4_addr_idx(ipv4_netdev, restrict_pcb->src_ip) < 0)){
            return EHIP_RET_ADDR_NOT_EXISTS;
        }

        /* 检查路由是否可达 */
        route_type = ipv4_route_lookup(sender->dts_addr, restrict_pcb->netdev, &route, NULL);
        if(route_type == ROUTE_TABLE_UNREACHABLE)
            return EHIP_RET_UNREACHABLE;
        sender->src_addr = restrict_pcb->src_ip;
    }

    if(route_type == ROUTE_TABLE_LOCAL || route_type == ROUTE_TABLE_LOCAL_SELF){
        if( !ipv4_netdev_flags_is_loopback_support(ehip_netdev_trait_ipv4_dev(route.netdev)) )
            return EHIP_RET_UNREACHABLE;
        sender->netdev = loopback_default_netdev();
        sender->loopback_virtual_hw_addr = route.netdev;
    }else{
        sender->netdev = route.netdev;
        sender->gw_addr = route.gateway;
    }

    if(!(ehip_netdev_flags_get(sender->netdev) & EHIP_NETDEV_STATUS_UP))
        return EHIP_RET_UNREACHABLE;

    sender->route_type = route_type;
    return 0;
}

static int udp_sender_refresh(struct udp_sender *sender){
    if(eh_diff_time(eh_get_clock_monotonic_time(), sender->last_check_time) > udp_sender_refresh_timeout){
        return udp_sender_force_refresh(sender);
    }
    return 0;
}

static enum change_callback_return arp_callback_udp_send(struct arp_changed_callback *callback_action){
    struct arp_changed_action *action = eh_container_of(callback_action, struct arp_changed_action, action);
    int ret;
    if(!arp_entry_neigh_is_valid(action->action.idx)){
        if(arp_get_table_entry(action->action.idx)->state != ARP_STATE_NUD_INCOMPLETE){
            if(action->pcb->opt.error_callback)
                action->pcb->opt.error_callback((udp_pcb_t)action->pcb, action->ip_msg->ip_hdr.dst_addr, action->udp_hdr.dest, EHIP_RET_UNREACHABLE);
            goto arp_query_fail;
        }
        return ARP_CALLBACK_CONTINUE;
    }

    ret = ip_message_tx_ready(action->ip_msg, 
        &arp_get_table_entry(action->action.idx)->hw_addr, (const uint8_t *)&action->udp_hdr);
    if(ret < 0)
        goto ip_message_tx_ready_error;

    ip_tx(action->ip_msg);
    eh_mem_pool_free(action->pcb->action_pool, action);
    return ARP_CALLBACK_ABORT;
ip_message_tx_ready_error:
arp_query_fail:
    ip_message_free(action->ip_msg);
    eh_mem_pool_free(action->pcb->action_pool, action);
    return ARP_CALLBACK_ABORT;
}

void udp_input(struct ip_message *ip_msg){
    int ret;
    struct udp_hdr *udp_hdr;
    struct udp_hdr udp_hdr_tmp;

    ret = ip_message_rx_read(ip_msg, (uint8_t**)&udp_hdr, sizeof(struct udp_hdr), (uint8_t*)&udp_hdr_tmp);
    if(ret != sizeof(struct udp_hdr)){
        goto drop;
    }
    eh_modeule_debugfl(UDP_INPUT, "############### INPUT RAW UDP PACKET ###############");
    eh_modeule_debugfl(UDP_INPUT, IPV4_FORMATIO":%d->"IPV4_FORMATIO":%d len:%d",ipv4_formatio(ip_msg->ip_hdr.src_addr), eh_ntoh16(udp_hdr->source),
        ipv4_formatio(ip_msg->ip_hdr.dst_addr), eh_ntoh16(udp_hdr->dest), eh_ntoh16(udp_hdr->len));
    eh_modeule_debugfl(UDP_INPUT, "check: %#hx", udp_hdr->check);
    if(!ip_message_flag_is_fragment(ip_msg)){
        eh_modeule_debugfl(UDP_INPUT,"payload %.*hhq", ehip_buffer_get_payload_size(ip_msg->buffer), 
            (uint8_t *)ehip_buffer_get_payload_ptr(ip_msg->buffer));
    }
drop:
    ip_message_free(ip_msg);
    return ;
}



udp_pcb_t ehip_udp_new(ipv4_addr_t bind_addr, uint16_be_t bind_port , ehip_netdev_t *netdev){
    struct udp_pcb_restrict *pcb;
    struct ipv4_netdev* ipv4_netdev;
    int ret;
    if(!netdev || (ipv4_netdev = ehip_netdev_trait_ipv4_dev(netdev)) == NULL )
        return eh_error_to_ptr(EH_RET_INVALID_PARAM);
    if(bind_addr != IPV4_ADDR_DHCP_CLIENT && !ipv4_netdev_is_ipv4_addr_valid(ipv4_netdev, bind_addr)){
        return eh_error_to_ptr(EH_RET_INVALID_PARAM);
    }

    pcb = (struct udp_pcb_restrict*)eh_malloc(sizeof(struct udp_pcb_restrict));
    if(pcb == NULL)
        return eh_error_to_ptr(EH_RET_MALLOC_ERROR);
    memset(pcb, 0, sizeof(struct udp_pcb_restrict));
    pcb->src_ip = bind_addr;
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

extern void ehip_udp_set_userdata(udp_pcb_t _pcb, void *userdata){
    struct udp_pcb *pcb = (struct udp_pcb *)_pcb;
    pcb->userdata = userdata;
}

extern void* ehip_udp_get_userdata(udp_pcb_t pcb){
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
    ipv4_addr_t dts_addr, uint16_be_t dts_port){
    struct udp_pcb *pcb = (struct udp_pcb *)_pcb;
    sender->pcb = _pcb;
    sender->arp_idx_cache = -1;
    sender->dts_addr = dts_addr;
    sender->dts_port = dts_port;
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

    if(sender->netdev == NULL)
        return EH_RET_INVALID_STATE;

    if(!sender->ip_msg){
        uint8_t ttl;
        if(sender->route_type == ROUTE_TABLE_MULTICAST && ipv4_is_local_multicast(sender->dts_addr)){
            ttl = 1;
        }else{
            ttl = EHIP_IP_DEFAULT_TTL;
        }
        sender->ip_msg = ip_message_tx_new(sender->netdev, ipv4_make_tos(0, 0), 
            ttl, udp_pcb_is_udplite(pcb)? IP_PROTO_UDPLITE : IP_PROTO_UDP, sender->src_addr, 
            sender->dts_addr, NULL, 0, sizeof(struct udp_hdr));
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
    struct ip_message *ip_msg = sender->ip_msg;
    ehip_buffer_t *pos_buffer;
    bool is_no_chksum = udp_pcb_is_nochksum(pcb);
    bool is_udplite = udp_pcb_is_udplite(pcb);
    int tmp_i;
    int ret = 0;
    struct arp_changed_action *arp_changed_action;
    ipv4_addr_t dst_addr_or_gw_addr;

    if(sender->ip_msg == NULL)
        return EH_RET_INVALID_PARAM;
    
    ret = udp_sender_refresh(sender);
    if(ret < 0)
        goto exit;

    if(sender->route_type == ROUTE_TABLE_UNREACHABLE){
        goto exit;
    }

    udp_hdr.source = sender->src_port;
    udp_hdr.dest = sender->dts_port;
    
    pseudo_header.src_ip = sender->src_addr;
    pseudo_header.dst_ip = sender->dts_addr;
    pseudo_header.zero = 0;

    if(is_udplite){
        /* udp lite TODO */
        ret = EH_RET_NOT_SUPPORTED;
        goto exit;
    }else{
        if(ip_message_flag_is_fragment(ip_msg)){
            ip_message_tx_fragment_for_each(pos_buffer, tmp_i, ip_msg){
                udp_fragment_len = ehip_buffer_get_payload_size(pos_buffer);
                udp_len += udp_fragment_len;
                if(!is_no_chksum)
                    udp_checksum = ehip_inet_chksum_accumulated(udp_checksum, ehip_buffer_get_payload_ptr(pos_buffer), udp_fragment_len);
            }
        }else{
            udp_len = ehip_buffer_get_payload_size(ip_msg->buffer);
            if(!is_no_chksum)
                udp_checksum = ehip_inet_chksum_accumulated(udp_checksum, ehip_buffer_get_payload_ptr(ip_msg->buffer), udp_len);
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
    // ip_message_tx_ready(ip_msg, , const uint8_t *head_data)
    
    if(sender->route_type == ROUTE_TABLE_MULTICAST && sender->gw_addr == IPV4_ADDR_ANY){
        /* 处理本地单播无需ARP */
        /* TODO */
        goto exit;
    }else if(sender->route_type == ROUTE_TABLE_BROADCAST){
        /* 处理广播无需ARP */
        ret = ip_message_tx_ready(ip_msg, ehip_netdev_trait_broadcast_hw(sender->netdev), (const uint8_t *)&udp_hdr);
        if(ret < 0)
            goto exit;
        ip_tx(sender->ip_msg);
        sender->ip_msg = NULL;
        return 0;

    }else if(sender->route_type == ROUTE_TABLE_LOCAL || sender->route_type == ROUTE_TABLE_LOCAL_SELF){
        /* TODO */
        ret = ip_message_tx_ready(ip_msg, (const ehip_hw_addr_t*)&sender->loopback_virtual_hw_addr, (const uint8_t *)&udp_hdr);
        if(ret < 0)
            goto exit;
        ip_tx(sender->ip_msg);
        sender->ip_msg = NULL;
        goto exit;
    }

    /* 单播，或者非局域网多播情况，需要进行ARP处理 */
    dst_addr_or_gw_addr = sender->gw_addr ? sender->gw_addr : sender->dts_addr;
    ret = arp_query(sender->netdev, dst_addr_or_gw_addr,sender->arp_idx_cache);
    if(ret == EH_RET_NOT_SUPPORTED){
        ret = ARP_MARS_IDX;
    }else if(ret < 0){
        eh_warnfl("arp_query fail %d", ret);
        goto exit;
    }

    /*  无论是否查询成功都需要缓存arp记录，方便下次快速查询 */
    sender->arp_idx_cache = ret;
    if(!arp_entry_neigh_is_valid(ret) && arp_get_table_entry(ret)->state != ARP_STATE_NUD_INCOMPLETE){
        ret = EHIP_RET_UNREACHABLE;
        goto exit;
    }

    if(arp_entry_neigh_is_valid(ret)){
        /* ARP查询成功 */
        ret = ip_message_tx_ready(ip_msg, (const ehip_hw_addr_t*)&arp_get_table_entry(ret)->hw_addr, (const uint8_t *)&udp_hdr);
        if(ret < 0)
            goto exit;
        ip_tx(sender->ip_msg);
        sender->ip_msg = NULL;
        return 0;
    }

    /* 检查是否在进行ARP查询状态中 */
    if(arp_get_table_entry(ret)->state != ARP_STATE_NUD_INCOMPLETE){
        /* ARP查询失败 */
        ret = EHIP_RET_UNREACHABLE;
        goto exit;
    }

    /* 进行ARP查询，注册ARP查询回调 */
    arp_changed_action = eh_mem_pool_alloc(pcb->action_pool);
    if(arp_changed_action == NULL){
        ret = EH_RET_MEM_POOL_EMPTY;
        goto exit;
    }
    arp_changed_action->action.callback = arp_callback_udp_send;
    arp_changed_action->action.idx = sender->arp_idx_cache;
    arp_changed_action->ip_msg = ip_msg;
    arp_changed_action->pcb = pcb;
    arp_changed_action->udp_hdr = udp_hdr;

    ret = arp_changed_callback_register(&arp_changed_action->action);
    if(ret < 0){
        eh_warnfl("arp_changed_callback_register fail %d", ret);
        goto make_ip_message_tx_fail;
    }
    sender->ip_msg = NULL;

    return 0;
make_ip_message_tx_fail:
    eh_mem_pool_free(pcb->action_pool, arp_changed_action);
exit:
    ehip_udp_sender_buffer_clean(sender);
    return ret;
}


int udp_socket_init(void){
    udp_hash_tbl = eh_hashtbl_create(EH_HASHTBL_DEFAULT_LOADFACTOR);
    if(eh_ptr_to_error(udp_hash_tbl) < 0)
        return eh_ptr_to_error(udp_hash_tbl);
    udp_sender_refresh_timeout = (eh_sclock_t)eh_msec_to_clock(UDP_SENDER_REFRESH_TIMEOUT);
    return 0;
}

void udp_socket_exit(void){
    eh_hashtbl_destroy(udp_hash_tbl);
}


ehip_protocol_module_export(udp_socket_init, udp_socket_exit);

