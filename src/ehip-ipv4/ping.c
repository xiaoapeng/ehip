/**
 * @file ping.c
 * @brief ping 回显应答，ping 发送请求实现
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-01-21
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */

#include "eh_debug.h"
#include "eh_types.h"
#include "ehip_buffer.h"
#include "ehip_core.h"
#include <eh.h>
#include <eh_signal.h>
#include <eh_mem_pool.h>
#include <ehip_module.h>
#include <ehip_conf.h>
#include <ehip_chksum.h>
#include <ehip-ipv4/ip.h>
#include <ehip-ipv4/ip_message.h>
#include <ehip-ipv4/arp.h>
#include <ehip-ipv4/route.h>
#include <ehip-ipv4/icmp.h>


struct arp_changed_action{
    struct arp_changed_callback action;
    struct ip_message  *echo_ip_reply_msg;
    struct route_info out_route;
};

static eh_mem_pool_t action_pool;

/**
 * @brief       回复ping请求,也作为ARP回调的函数，此函数返回时要消耗掉callback_actiona
 * @param  callback_actiona 
 * @return enum change_callback_return 
 */
static enum change_callback_return ping_echo_reply(struct arp_changed_callback *callback_actiona){
    int ret;
    int tmp_i;
    ehip_buffer_t *pos_buffer;
    ehip_buffer_t *tx_pos_buffer;
    struct arp_changed_action *actiona = eh_container_of(callback_actiona, struct arp_changed_action, action);

    if(!arp_entry_neigh_is_valid(actiona->action.idx)){
        if(arp_get_table_entry(actiona->action.idx)->state !=  ARP_STATE_NUD_INCOMPLETE){
            goto arp_query_fail;
        }
        return ARP_CALLBACK_CONTINUE;
    }

    ret = ip_message_tx_ready(actiona->echo_ip_reply_msg, &arp_get_table_entry(actiona->action.idx)->hw_addr);
    if(ret < 0)
        goto ip_message_tx_ready_error;

    if(ip_message_flag_is_fragment(actiona->echo_ip_reply_msg)){
        ip_message_tx_fragment_for_each(pos_buffer, tmp_i, actiona->echo_ip_reply_msg){
            tx_pos_buffer = ehip_buffer_ref_dup(pos_buffer);
            ehip_queue_tx(tx_pos_buffer);
        }
    }else{
        tx_pos_buffer = ehip_buffer_ref_dup(actiona->echo_ip_reply_msg->buffer);
        ehip_queue_tx(tx_pos_buffer);
    }
    
ip_message_tx_ready_error:
arp_query_fail:
    ip_message_free(actiona->echo_ip_reply_msg);
    eh_mem_pool_free(action_pool, actiona);
    return ARP_CALLBACK_ABORT;
}





static void ping_echo_server(struct ip_message *ip_msg, const struct icmp_hdr *icmp_hdr){
    int ret;
    enum route_table_type route_type;
    struct arp_changed_action *callback_actiona;
    int arp_idx;
    ipv4_addr_t dst_addr_or_gw_addr;
    struct ip_message *ip_msg_reply;
    struct icmp_hdr *icmp_hdr_reply;
    ehip_buffer_t *out_buffer;
    ehip_buffer_size_t out_buffer_capacity_size;
    ehip_buffer_size_t data_size;
    ehip_buffer_size_t single_data_size;
    uint8_t *write_ptr;
    callback_actiona = eh_mem_pool_alloc(action_pool);
    if(callback_actiona == NULL){
        goto eh_mem_pool_alloc_fail;
    }

    /* 准备回复 */
    
    /* 查路由表，找到最佳路径 */
    route_type = ipv4_route_lookup(ip_msg->ip_hdr.src_addr, &callback_actiona->out_route);
    if(route_type != ROUTE_TABLE_UNICAST && route_type != ROUTE_TABLE_ANYCAST){
        goto unreachable_target;
    }

    dst_addr_or_gw_addr = callback_actiona->out_route.gateway ? 
        callback_actiona->out_route.gateway : ip_msg->ip_hdr.src_addr;
    arp_idx = arp_query(callback_actiona->out_route.netdev, dst_addr_or_gw_addr, -1);
    if(arp_idx == EH_RET_NOT_SUPPORTED){
        arp_idx = ARP_MARS_IDX;
    }else if(arp_idx < 0){
        eh_warnfl("arp_query fail %d", arp_idx);
        goto unreachable_target;
    }

    callback_actiona->action.callback = ping_echo_reply;
    callback_actiona->action.idx = arp_idx;

    if(!arp_entry_neigh_is_valid(arp_idx) && arp_get_table_entry(arp_idx)->state != ARP_STATE_NUD_INCOMPLETE){
        goto unreachable_target;
    }

    /* 生成回复的 ip报文 */
    ip_msg_reply = ip_message_tx_new(callback_actiona->out_route.netdev, ipv4_make_tos(0, 0), 
        EHIP_IP_DEFAULT_TTL, IP_PROTO_ICMP, ip_msg->ip_hdr.dst_addr, ip_msg->ip_hdr.src_addr, NULL, 0);
    if(ip_msg_reply == NULL)
        goto unreachable_target;
    
    ret = ip_message_tx_add_buffer(ip_msg_reply, &out_buffer, &out_buffer_capacity_size);
    if(ret < 0 || out_buffer_capacity_size < sizeof(struct icmp_hdr))
        goto make_ip_message_tx_fail;

    ret = ip_message_rx_data_size(ip_msg);
    if(ret < 0)
        goto make_ip_message_tx_fail;

    data_size = (ehip_buffer_size_t)ret;

    if(data_size > out_buffer_capacity_size - sizeof(struct icmp_hdr)){
        /* 说明回复的数据量较大，需要分片， out_buffer_capacity_size 需要对齐8字节 */
        out_buffer_capacity_size =  out_buffer_capacity_size & (ehip_buffer_size_t)(~7);
    }

    /* append 合适的大小 */
    single_data_size = data_size + sizeof(struct icmp_hdr);
    single_data_size = out_buffer_capacity_size > single_data_size ? 
        single_data_size : out_buffer_capacity_size;
    icmp_hdr_reply = (struct icmp_hdr *)ehip_buffer_payload_append(out_buffer, single_data_size);
    if(icmp_hdr_reply == NULL)
        goto make_ip_message_tx_fail;

    icmp_hdr_reply->type = ICMP_TYPE_ECHO_REPLY;
    icmp_hdr_reply->code = 0;
    icmp_hdr_reply->checksum = 0;
    icmp_hdr_reply->echo.id = icmp_hdr->echo.id;
    icmp_hdr_reply->echo.sequence = icmp_hdr->echo.sequence;

    icmp_hdr_reply->checksum = ehip_inet_chksum((uint16_t *)icmp_hdr_reply, sizeof(struct icmp_hdr));

    write_ptr = (uint8_t *)(icmp_hdr_reply + 1);

    single_data_size = single_data_size - (ehip_buffer_size_t)(sizeof(struct icmp_hdr));
    ret = ip_message_rx_real_read(ip_msg, write_ptr, single_data_size);
    if(ret < 0)
        goto make_ip_message_tx_fail;
    
    icmp_hdr_reply->checksum = ehip_inet_chksum_accumulated(icmp_hdr_reply->checksum,
        (uint16_t *)write_ptr, single_data_size);
    data_size -= single_data_size;

    while(data_size){
        ret = ip_message_tx_add_buffer(ip_msg_reply, &out_buffer, &out_buffer_capacity_size);
        if(ret < 0)
            goto make_ip_message_tx_fail;
        single_data_size = out_buffer_capacity_size > data_size ? 
            data_size : out_buffer_capacity_size;
        write_ptr = ehip_buffer_payload_append(out_buffer, single_data_size);
        if(write_ptr == NULL)
            goto make_ip_message_tx_fail;
        ret = ip_message_rx_real_read(ip_msg, write_ptr, single_data_size);
        if(ret < 0)
            goto make_ip_message_tx_fail;
        icmp_hdr_reply->checksum = ehip_inet_chksum_accumulated(icmp_hdr_reply->checksum,
            (uint16_t *)write_ptr, single_data_size);
        data_size -= single_data_size;
    }
    ip_message_free(ip_msg);

    callback_actiona->echo_ip_reply_msg = ip_msg_reply;

    if(arp_entry_neigh_is_valid(arp_idx))
        ping_echo_reply(&callback_actiona->action);
    else{
        ret = arp_changed_callback_register(&callback_actiona->action);
        if(ret < 0){
            eh_warnfl("arp_changed_callback_register fail %d", ret);
            goto make_ip_message_tx_fail;
        }
    }
    return ;
make_ip_message_tx_fail:
    ip_message_free(ip_msg_reply);
unreachable_target:
    eh_mem_pool_free(action_pool, callback_actiona);
eh_mem_pool_alloc_fail:
    ip_message_free(ip_msg);
}


void ping_input(struct ip_message *ip_msg, const struct icmp_hdr *icmp_hdr){
    if(icmp_hdr->type == ICMP_TYPE_ECHO){
        ping_echo_server(ip_msg, icmp_hdr);
        return ;
    }
    ip_message_free(ip_msg);
    return ;
}

static int __init  ping_init(void){
    action_pool = eh_mem_pool_create(EHIP_POOL_BASE_ALIGN, sizeof(struct arp_changed_action), EHIP_PING_ARP_CHANGED_ACTION_CNT);
    if(eh_ptr_to_error(action_pool) < 0)
        return eh_ptr_to_error(action_pool);
    return 0;
}

static void __exit ping_exit(void){
    int i=0;
    struct arp_changed_action *action;
    eh_mem_pool_for_each(i, action_pool, action){
        if(eh_mem_pool_idx_is_used(action_pool, i)){
            ip_message_free(action->echo_ip_reply_msg);
        }
    }

    eh_mem_pool_destroy(action_pool);
    return ;
}


ehip_protocol_module_export(ping_init, ping_exit);


