/**
 * @file ip_tx.c
 * @brief 发送ip包
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-03-18
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */

#include <eh.h>
#include <eh_error.h>
#include <eh_mem_pool.h>
#include <eh_debug.h>
#include <eh_signal.h>
#include <ehip_error.h>
#include <ehip_module.h>
#include <ehip_core.h>
#include <ehip_buffer.h>
#include <ehip-ipv4/ip.h>
#include <ehip-ipv4/ip_tx.h>
#include <ehip-ipv4/arp.h>
#include <ehip-ipv4/ip_message.h>
#include <ehip-ipv4/ip_raw_error.h>


static eh_mem_pool_t arp_query_pool;

struct arp_query_pcb{
    int arp_idx;
    struct ip_message *ip_msg;
    ipv4_addr_t dst_addr_or_gw_addr;
};
static int ip_tx_done(struct ip_message *ip_msg, const ehip_hw_addr_t* hw_addr);

static void slot_function_arp_changed(eh_event_t *e, void *param){
    (void) e;
    (void) param;
    int i;
    struct arp_query_pcb *ptr;
    eh_mem_pool_for_each(i, arp_query_pool, ptr){
        if(!eh_mem_pool_idx_is_used(arp_query_pool, i))
            continue;
        /* 进行 arp 查询，看是否有效 */
        eh_mdebugfl(IP_TX, "arp changed [" IPV4_FORMATIO "]->[" IPV4_FORMATIO "]", 
                ipv4_formatio(ptr->ip_msg->ip_hdr.src_addr), ipv4_formatio(ptr->ip_msg->ip_hdr.dst_addr));
        if(arp_entry_neigh_is_valid(ptr->arp_idx)){
            eh_mdebugfl(IP_TX, "arp query [" IPV4_FORMATIO "]=[%.*hhq]", ipv4_formatio(ptr->dst_addr_or_gw_addr), EHIP_ETH_HWADDR_MAX_LEN, &arp_get_table_entry(ptr->arp_idx)->hw_addr);
            ip_tx_done(ptr->ip_msg, (const ehip_hw_addr_t*)&arp_get_table_entry(ptr->arp_idx)->hw_addr);
            eh_mem_pool_free(arp_query_pool, ptr);
        }else if(arp_get_table_entry(ptr->arp_idx)->state != ARP_STATE_NUD_INCOMPLETE){
            struct ip_message *ip_msg = ptr->ip_msg;
            uint8_t *payload;
            int payload_len;
            ehip_buffer_t *head_payload;
            eh_mdebugfl(IP_TX, "arp query [" IPV4_FORMATIO "]=[ERROR]", ipv4_formatio(ptr->dst_addr_or_gw_addr));
            /* 进行错误处理 */
            // 调用ip_raw_error(ipv4_addr_t err_sender, struct ip_hdr *ip_hdr, const uint8_t *payload, int payload_len, int error)
            if(ip_message_flag_is_fragment(ip_msg)){
                head_payload = ip_message_rx_fragment_first(ip_msg);
            }else{
                head_payload = ip_message_first(ip_msg);
            }
            payload = ehip_buffer_get_payload_ptr(head_payload) + ipv4_hdr_len(&ip_msg->ip_hdr);
            payload_len = ehip_buffer_get_payload_size(head_payload) - ipv4_hdr_len(&ip_msg->ip_hdr);
            if(payload_len <= 0){
                payload = NULL;
                payload_len = 0;
            }

            ip_raw_error(ip_msg->ip_hdr.src_addr, &ip_msg->ip_hdr, payload, payload_len, EHIP_RET_UNREACHABLE);
            ip_message_free(ip_msg);
            eh_mem_pool_free(arp_query_pool, ptr);
        }

    }

}

static EH_DEFINE_SLOT(slot_arp_table_changed, slot_function_arp_changed, NULL);


static int arp_query_add(struct ip_message *ip_msg, ipv4_addr_t dst_addr_or_gw_addr, int arp_idx){
    int ret = 0;
    struct arp_query_pcb *new_query = eh_mem_pool_alloc(arp_query_pool);

    if(new_query == NULL){
        ret = EH_RET_MEM_POOL_EMPTY;
        goto error;
    }
    new_query->arp_idx = arp_idx;
    new_query->dst_addr_or_gw_addr = dst_addr_or_gw_addr;
    new_query->ip_msg = ip_msg;
    return 0;
error:
    ip_message_free(ip_msg);
    return ret;
}

static int ip_tx_done(struct ip_message *ip_msg, const ehip_hw_addr_t* hw_addr){
    int ret = 0;
    ehip_buffer_t *pos_buffer;
    ehip_buffer_t *tx_pos_buffer;
    int tmp_i;
    ehip_netdev_t *netdev;

    if(ip_message_flag_is_fragment(ip_msg)){
        ip_message_tx_fragment_for_each(pos_buffer, tmp_i, ip_msg){
            netdev = pos_buffer->netdev;
            /* 填充链路层头部 */
            ret = ehip_netdev_trait_hard_header(netdev, pos_buffer, 
                ehip_netdev_trait_hw_addr(netdev), hw_addr,
                EHIP_PTYPE_ETHERNET_IP, ehip_buffer_get_payload_size(pos_buffer));
            if(ret < 0)
                goto quit;
            ret = ehip_netdev_trait_buffer_padding(netdev, pos_buffer);
            if(ret < 0)
                goto quit;

            tx_pos_buffer = ehip_buffer_ref_dup(pos_buffer);
            if(eh_ptr_to_error(tx_pos_buffer) < 0){
                ret = eh_ptr_to_error(tx_pos_buffer);
                goto quit;
            }
            ehip_queue_tx(tx_pos_buffer);
        }
    }else{
        netdev = ip_message_first(ip_msg)->netdev;
        ret = ehip_netdev_trait_hard_header(netdev, ip_message_first(ip_msg), 
            ehip_netdev_trait_hw_addr(netdev), hw_addr,
            EHIP_PTYPE_ETHERNET_IP, ehip_buffer_get_payload_size(ip_message_first(ip_msg)));
        if(ret < 0)
            goto quit;
        ret = ehip_netdev_trait_buffer_padding(netdev, ip_message_first(ip_msg));
        if(ret < 0)
            goto quit;
        tx_pos_buffer = ehip_buffer_ref_dup(ip_message_first(ip_msg));
        if(eh_ptr_to_error(tx_pos_buffer) < 0){
            ret = eh_ptr_to_error(tx_pos_buffer);
            goto quit;
        }
        ehip_queue_tx(tx_pos_buffer);
    }
quit:
    ip_message_free(ip_msg);
    return ret;
}

int ip_tx(ehip_netdev_t *netdev, struct ip_message *ip_msg, int *arp_idx, ipv4_addr_t gw){
    int ret = 0;
    const ehip_hw_addr_t* hw_addr = NULL;
    ipv4_addr_t dst_addr_or_gw_addr;

    if(!ip_message_flag_is_tx(ip_msg) || !ip_message_flag_is_tx_ready(ip_msg)){
        ret = EH_RET_INVALID_PARAM;
        goto quit;
    }
    
    /* 进行ARP查询 */
    switch(ip_message_route_type(ip_msg)) {
        case ROUTE_TABLE_UNICAST:
            dst_addr_or_gw_addr = gw ? gw : ip_msg->ip_hdr.dst_addr;
            ret = arp_query(netdev, dst_addr_or_gw_addr, *arp_idx);
            if(ret == EH_RET_NOT_SUPPORTED)
                break;
            if(ret < 0){
                eh_mwarnfl(IP_TX, "arp query failed %d", ret);
                goto quit;
            }
            *arp_idx = ret;
            if(!arp_entry_neigh_is_valid(*arp_idx)){
                /* 要进行ARP慢查询 */
                return arp_query_add(ip_msg, dst_addr_or_gw_addr, *arp_idx);
            }
            hw_addr = (const ehip_hw_addr_t*)&arp_get_table_entry(ret)->hw_addr;
            break;
        case ROUTE_TABLE_LOCAL:
        case ROUTE_TABLE_LOCAL_SELF:
            hw_addr = &netdev;
            break;

        case ROUTE_TABLE_BROADCAST:
            hw_addr = ehip_netdev_trait_broadcast_hw(netdev);
            break;
        default:
            ret = EHIP_RET_UNREACHABLE;
            goto quit;
    }
    ip_tx_done(ip_msg, hw_addr);
    return 0;

quit:
    ip_message_free(ip_msg);
    return ret;
}

int __init ip_tx_init(void){
    int ret;
    arp_query_pool = eh_mem_pool_create(EHIP_POOL_BASE_ALIGN, sizeof(struct arp_query_pcb), EHIP_ARP_QUERY_MEM_POOL_NUM);
    ret = eh_ptr_to_error(arp_query_pool);
    if(ret < 0)
        return ret;
    eh_signal_slot_connect(&signal_arp_table_changed, &slot_arp_table_changed);
    return 0;
}

void __exit ip_tx_exit(void){
    int i;
    struct arp_query_pcb *ptr;
    eh_signal_slot_disconnect(&slot_arp_table_changed);
    eh_mem_pool_for_each(i, arp_query_pool, ptr){
        if(eh_mem_pool_idx_is_used(arp_query_pool, i)){
            ip_message_free(((struct arp_query_pcb *)ptr)->ip_msg);
            eh_mem_pool_free(arp_query_pool, ptr);
        }
    }
    eh_mem_pool_destroy(arp_query_pool);
}

ehip_protocol_module_export(ip_tx_init, ip_tx_exit);
