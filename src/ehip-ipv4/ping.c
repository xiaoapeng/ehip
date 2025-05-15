/**
 * @file ping.c
 * @brief ping 回显应答，ping 发送请求实现
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-01-21
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */

#include <stddef.h>
#include <stdint.h>

#include <eh.h>
#include <eh_platform.h>
#include <eh_debug.h>
#include <eh_types.h>
#include <eh_event.h>
#include <eh_event_cb.h>
#include <eh_timer.h>
#include <eh_signal.h>
#include <eh_mem_pool.h>
#include <ehip_buffer.h>
#include <ehip_error.h>
#include <ehip_core.h>
#include <ehip_module.h>
#include <ehip_conf.h>
#include <ehip_chksum.h>
#include <ehip_netdev_trait.h>
#include <ehip-ipv4/ip.h>
#include <ehip-ipv4/ip_message.h>
#include <ehip-ipv4/arp.h>
#include <ehip-ipv4/route.h>
#include <ehip-ipv4/icmp.h>
#include <ehip-ipv4/ip_tx.h>
#include <ehip-ipv4/ping.h>
#include <ehip-mac/loopback.h>


#define PING_SENDER_REFRESH_TIMEOUT   1000ULL

#define PING_PCB_PRIVATE_FLAGS_ANY          0x00000001U
#define PING_PCB_PRIVATE_FLAGS_BIT_WIDTH    4

#define PING_REQUEST_TIMEOUT_DEFAULT        10   /* 100*100ms */

#define ping_pcb_is_any(pcb)  ((pcb)->flags & PING_PCB_PRIVATE_FLAGS_ANY)
#define ping_pcb_is_busy(pcb) ((pcb)->flags & PING_PCB_PRIVATE_FLAGS_BUSY)

struct __packed ping_request{
    struct  icmp_hdr    icmp_hdr;
    eh_clock_t          timestamp;
};


struct ping_opt{
    void (*response_callback)(ping_pcb_t pcb, ipv4_addr_t addr, uint16_t seq, uint8_t ttl, eh_clock_t time_ms);
    void (*error_callback)(ping_pcb_t pcb, ipv4_addr_t addr, uint16_t seq, int erron);
};


struct ping_pcb{
    void                                        *userdata;
    uint32_t                                    flags;
    ipv4_addr_t                                 src_addr;
    ipv4_addr_t                                 dst_addr;
    struct ehip_netdev                          *netdev;
    enum route_table_type                       route_type;
    ipv4_addr_t                                 gw_addr;
    eh_clock_t                                  last_check_time;
    uint16_t                                    seq;
    uint8_t                                     ttl;
    uint8_t                                     timeout;
    eh_signal_slot_t                            slot_timeout;
    EH_STRUCT_CUSTOM_SIGNAL(eh_event_timer_t)   signal_timeout;
    int                                         idx;
    struct ping_opt                             opt;
};


static eh_mem_pool_t ping_pcb_pool;

static void slot_function_recv_timeout(eh_event_t *e, void *slot_param){
    (void)e;
    struct ping_pcb *pcb = (struct ping_pcb *)slot_param;
    if(pcb->opt.error_callback)
        pcb->opt.error_callback((ping_pcb_t)pcb, pcb->src_addr, pcb->seq, EH_RET_TIMEOUT);
}

static void ping_echo_server(struct ip_message *ip_msg, const struct icmp_hdr *icmp_hdr){
    int ret;
    enum route_table_type route_type;
    int arp_idx;
    struct ip_message *ip_msg_reply;
    struct icmp_hdr *icmp_hdr_reply;
    ehip_buffer_t *out_buffer;
    ehip_buffer_size_t out_buffer_capacity_size;
    ehip_buffer_size_t data_size;
    ehip_buffer_size_t single_data_size;
    uint8_t *write_ptr;
    ehip_netdev_t *netdev;
    struct route_info  out_route;
    ipv4_addr_t  best_src_addr;

    /* 准备回复 */
    netdev = ip_message_get_netdev(ip_msg);
    /* 查路由表，找到最佳路径 */
    route_type = ipv4_route_lookup(ip_msg->ip_hdr.src_addr, netdev, &out_route, &best_src_addr);
    if(route_type != ROUTE_TABLE_UNICAST && route_type != ROUTE_TABLE_LOCAL_SELF){
        goto unreachable_target;
    }

    if(!ipv4_netdev_is_local_broadcast(ehip_netdev_trait_ipv4_dev(netdev), ip_msg->ip_hdr.dst_addr) && !ipv4_is_global_bcast(ip_msg->ip_hdr.dst_addr)){
        /* 目的地址不是本地广播地址 */
        best_src_addr = ip_msg->ip_hdr.dst_addr;
    }

    /* 生成回复的 ip报文,header_reserved_size将设置为0，因为下面会将icmp头部当作数据的一部分来处理 */
    ip_msg_reply = ip_message_tx_new(netdev, ipv4_make_tos(0, 0), 
        EHIP_IP_DEFAULT_TTL, IP_PROTO_ICMP, best_src_addr, ip_msg->ip_hdr.src_addr, NULL, 0, 0, route_type);
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

    ret = ip_message_tx_ready(ip_msg_reply, NULL);
    if(ret < 0)
        goto ip_message_tx_ready_error;
    arp_idx = -1;
    ip_tx(netdev, ip_msg_reply, &arp_idx, out_route.gateway);
    ip_message_free(ip_msg);
    return ;
ip_message_tx_ready_error:
make_ip_message_tx_fail:
    ip_message_free(ip_msg_reply);
unreachable_target:
    ip_message_free(ip_msg);
}



static ping_pcb_t _ehip_ping_new(ipv4_addr_t src_addr, ipv4_addr_t dst_addr, ehip_netdev_t *netdev, uint32_t flags){
    struct ping_pcb *pcb;
    int ret;
    if( ipv4_is_global_bcast(src_addr) ||
        ipv4_is_global_bcast(dst_addr))
        return eh_error_to_ptr(EH_RET_INVALID_PARAM);
    
    pcb = (struct ping_pcb *)eh_mem_pool_alloc(ping_pcb_pool);
    if(pcb == NULL)
        return eh_error_to_ptr(EH_RET_MEM_POOL_EMPTY);
    memset(pcb, 0, sizeof(*pcb));
    pcb->userdata = NULL;
    pcb->flags = flags;
    pcb->src_addr = src_addr;
    pcb->dst_addr = dst_addr;
    pcb->netdev = netdev;
    pcb->ttl = EHIP_IP_DEFAULT_TTL;
    pcb->timeout = PING_REQUEST_TIMEOUT_DEFAULT;
    pcb->idx = -1;
    eh_event_cb_slot_init(&pcb->slot_timeout, slot_function_recv_timeout, pcb);
    eh_signal_init(&pcb->signal_timeout);
    eh_timer_advanced_init(eh_signal_to_custom_event(&pcb->signal_timeout), 
        (eh_sclock_t)eh_msec_to_clock(PING_REQUEST_TIMEOUT_DEFAULT * 100) , 0);
    ret = eh_signal_register(&pcb->signal_timeout);
    if(ret < 0)
        goto eh_signal_register;
    eh_signal_slot_connect(&pcb->signal_timeout, &pcb->slot_timeout);

    return (ping_pcb_t)pcb;
eh_signal_register:
    eh_mem_pool_free(ping_pcb_pool, pcb);
    return eh_error_to_ptr(ret);
}

static void ping_echo_reply(struct ip_message *ip_msg, const struct icmp_hdr *icmp_hdr){
    uint16_t id = icmp_hdr->echo.id;
    struct ping_pcb *pcb;
    eh_clock_t timestamp;
    eh_sclock_t diff_timestamp;
    if( id >= EHIP_PING_PCB_NUM || !eh_mem_pool_idx_is_used(ping_pcb_pool, id) )
        goto exit;

    pcb = eh_mem_pool_idx_to_ptr(ping_pcb_pool, id);
    if( pcb->seq <= icmp_hdr->echo.sequence || 
        pcb->src_addr != ip_msg->ip_hdr.dst_addr )
        goto exit;
    
    if(pcb->opt.response_callback == NULL)
        goto exit;

    if(ip_message_rx_real_read(ip_msg, (uint8_t *)&timestamp, sizeof(timestamp)) != sizeof(timestamp))
        goto exit;

    diff_timestamp = eh_diff_time(eh_get_clock_monotonic_time(), timestamp);
    if(diff_timestamp < 0)
        goto exit;
    if( pcb->seq -1 == icmp_hdr->echo.sequence)
        eh_timer_stop(eh_signal_to_custom_event(&pcb->signal_timeout));
    pcb->opt.response_callback((ping_pcb_t)pcb, pcb->dst_addr, icmp_hdr->echo.sequence, ip_msg->ip_hdr.ttl, (eh_clock_t)diff_timestamp);
exit:
    ip_message_free(ip_msg);
}

void ping_input(struct ip_message *ip_msg, const struct icmp_hdr *icmp_hdr){
    if(icmp_hdr->type == ICMP_TYPE_ECHO){
        ping_echo_server(ip_msg, icmp_hdr);
        return ;
    }else if(icmp_hdr->type == ICMP_TYPE_ECHO_REPLY){
        ping_echo_reply(ip_msg, icmp_hdr);
        return ;
    }
    ip_message_free(ip_msg);
    return ;
}

void ping_error_input(ipv4_addr_t err_sender, struct ip_hdr *ip_hdr, const uint8_t *payload, int payload_len, int error){
    const struct icmp_hdr *icmp_hdr;
    uint16_t id;
    struct ping_pcb *pcb;
    if(payload_len < (int)sizeof(struct icmp_hdr))
        return ;

    icmp_hdr = (const struct icmp_hdr *)payload;
    if(icmp_hdr->type != ICMP_TYPE_ECHO)
        return ;
    id = icmp_hdr->echo.id;
    
    if( id >= EHIP_PING_PCB_NUM || !eh_mem_pool_idx_is_used(ping_pcb_pool, id) )
        return ;

    pcb = eh_mem_pool_idx_to_ptr(ping_pcb_pool, id);
    if( pcb->seq <= icmp_hdr->echo.sequence || 
        pcb->src_addr != ip_hdr->src_addr ||
        pcb->dst_addr != ip_hdr->dst_addr )
        return ;

    if( pcb->seq -1 == icmp_hdr->echo.sequence)
        eh_timer_stop(eh_signal_to_custom_event(&pcb->signal_timeout));

    if(pcb->opt.error_callback == NULL)
        return ;
    pcb->opt.error_callback((ping_pcb_t)pcb, err_sender, icmp_hdr->echo.sequence, error);
    
}

ping_pcb_t ehip_ping_new(ipv4_addr_t src_addr, ipv4_addr_t dst_addr, ehip_netdev_t *netdev){
    return _ehip_ping_new(src_addr, dst_addr, netdev, 0);
}

ping_pcb_t ehip_ping_any_new(ipv4_addr_t dst_addr){
    return _ehip_ping_new(IPV4_ADDR_ANY, dst_addr, NULL, PING_PCB_PRIVATE_FLAGS_ANY);
}


void ehip_ping_delete(ping_pcb_t _pcb){
    struct ping_pcb *pcb = (struct ping_pcb *)_pcb;
    eh_timer_stop(eh_signal_to_custom_event(&pcb->signal_timeout));
    eh_signal_slot_disconnect(&pcb->slot_timeout);
    eh_signal_unregister(&pcb->signal_timeout);
    eh_mem_pool_free(ping_pcb_pool, pcb);
}

void ehip_ping_set_userdata(ping_pcb_t _pcb, void *userdata){
    struct ping_pcb *pcb = (struct ping_pcb *)_pcb;
    pcb->userdata = userdata;
}

void* ehip_ping_get_userdata(ping_pcb_t _pcb){
    struct ping_pcb *pcb = (struct ping_pcb *)_pcb;
    return pcb->userdata;
}

void ehip_ping_set_timeout(ping_pcb_t _pcb, uint8_t timeout){
    struct ping_pcb *pcb = (struct ping_pcb *)_pcb;
    pcb->timeout = timeout;
    eh_timer_config_interval(eh_signal_to_custom_event(&pcb->signal_timeout), 
        (eh_sclock_t)eh_msec_to_clock(pcb->timeout * 100));
}

void ehip_ping_set_ttl(ping_pcb_t _pcb, uint8_t ttl){
    struct ping_pcb *pcb = (struct ping_pcb *)_pcb;
    pcb->ttl = ttl;
}


void ehip_ping_set_response_callback(ping_pcb_t _pcb, 
    void (*response_callback)(ping_pcb_t pcb, ipv4_addr_t addr, uint16_t seq, uint8_t ttl, eh_clock_t time_ms)){
    struct ping_pcb *pcb = (struct ping_pcb *)_pcb;
    pcb->opt.response_callback = response_callback;
}

extern void ehip_ping_set_error_callback(ping_pcb_t _pcb, 
    void (*error_callback)(ping_pcb_t pcb, ipv4_addr_t addr, uint16_t seq, int erron)){
    struct ping_pcb *pcb = (struct ping_pcb *)_pcb;
    pcb->opt.error_callback = error_callback;
}

int ehip_ping_request(ping_pcb_t _pcb, uint16_t data_len){
    struct ping_pcb *pcb = (struct ping_pcb *)_pcb;
    eh_clock_t now;
    ehip_buffer_t *out_buffer;
    ehip_buffer_size_t out_buffer_capacity_size;
    int ret;
    struct ping_request *ping_request;
    uint16_t single_data_size;
    uint8_t *write_ptr;
    uint8_t val = 0;
    struct ip_message *ip_msg;

    if((size_t)data_len < sizeof(eh_sclock_t))
        data_len = sizeof(eh_sclock_t);

    now = eh_get_clock_monotonic_time();
    if( pcb->route_type == ROUTE_TABLE_UNREACHABLE || 
        eh_diff_time(now, pcb->last_check_time) > 
            (eh_sclock_t)eh_msec_to_clock(PING_SENDER_REFRESH_TIMEOUT)){

        enum route_table_type route_type;
        struct route_info route;
        ipv4_addr_t best_src_addr;
        pcb->route_type = ROUTE_TABLE_UNREACHABLE;
        pcb->last_check_time = now;
        if(ping_pcb_is_any(pcb)){
            /* 检查路由是否可达 */
            route_type = ipv4_route_lookup(pcb->dst_addr, NULL, &route, &best_src_addr);
            if(route_type == ROUTE_TABLE_UNREACHABLE)
                return EHIP_RET_UNREACHABLE;
            pcb->src_addr = best_src_addr;
            pcb->netdev = route.netdev;
        }else{
            struct ipv4_netdev *ipv4_netdev;
            ipv4_netdev = ehip_netdev_trait_ipv4_dev(pcb->netdev);
            if(ipv4_netdev_get_ipv4_addr_idx(ipv4_netdev, pcb->src_addr) < 0)
                return EHIP_RET_ADDR_NOT_EXISTS;
            route_type = ipv4_route_lookup(pcb->dst_addr, pcb->netdev, &route, &best_src_addr);
            if(route_type == ROUTE_TABLE_UNREACHABLE)
                return EHIP_RET_UNREACHABLE;
        }

        if( route_type == ROUTE_TABLE_BROADCAST || route_type == ROUTE_TABLE_MULTICAST )
            return EHIP_RET_UNREACHABLE;

        if( (route_type == ROUTE_TABLE_LOCAL || route_type == ROUTE_TABLE_LOCAL_SELF ) && 
            (   !ipv4_netdev_flags_is_loopback_support(ehip_netdev_trait_ipv4_dev(pcb->netdev)) ||
                !(ehip_netdev_flags_get(loopback_default_netdev()) & EHIP_NETDEV_STATUS_UP)     )
        ){
            return EHIP_RET_UNREACHABLE;
        }

        if(!(ehip_netdev_flags_get(pcb->netdev) & EHIP_NETDEV_STATUS_UP))
            return EHIP_RET_UNREACHABLE;
        pcb->route_type = route_type;
        pcb->gw_addr = route.gateway;
    }

    ip_msg = ip_message_tx_new(pcb->netdev, ipv4_make_tos(0,0), pcb->ttl, IP_PROTO_ICMP, 
        pcb->src_addr, pcb->dst_addr, NULL, 0, 0, pcb->route_type);
    if(ip_msg == NULL)
        return EH_RET_MEM_POOL_EMPTY;

    ret = ip_message_tx_add_buffer(ip_msg, &out_buffer, &out_buffer_capacity_size);
    if(ret < 0)
        goto free_ip_msg_quit;

    if(out_buffer_capacity_size < sizeof(struct ping_request)){
        eh_mwarnfl(PING_REQUEST, "out_buffer_capacity_size < sizeof(struct ping_request)!");
        ret = EH_RET_INVALID_STATE;
        goto free_ip_msg_quit;
    }

    ping_request = (struct ping_request*)ehip_buffer_payload_append(out_buffer, sizeof(struct ping_request));
    ping_request->icmp_hdr.type = ICMP_TYPE_ECHO;
    ping_request->icmp_hdr.code = 0;
    ping_request->icmp_hdr.checksum = 0;
    /* 这里不转换字节序，可以得到一些性能 */
    ping_request->icmp_hdr.echo.id = (uint16_be_t)eh_mem_pool_ptr_to_idx(ping_pcb_pool, pcb);
    ping_request->icmp_hdr.echo.sequence = (uint16_be_t)pcb->seq;
    /* ping_request->timestamp 会在发送的时候再去赋值，避免将arp请求时间计算在内  */
    ping_request->timestamp = now;
    ping_request->icmp_hdr.checksum = ehip_inet_chksum_accumulated(ping_request->icmp_hdr.checksum, ping_request, sizeof(struct ping_request));

    data_len -= (uint16_t)sizeof(eh_clock_t);

    while(data_len){
        ret = ip_message_tx_add_buffer(ip_msg, &out_buffer, &out_buffer_capacity_size);
        if(ret < 0)
            goto free_ip_msg_quit;
        single_data_size = data_len > out_buffer_capacity_size ? out_buffer_capacity_size : data_len;
        write_ptr = ehip_buffer_payload_append(out_buffer, single_data_size);
        for(int i = 0; i < single_data_size; i++)
            write_ptr[i] = val++;
        ping_request->icmp_hdr.checksum = ehip_inet_chksum_accumulated(ping_request->icmp_hdr.checksum, write_ptr, single_data_size);
        data_len -= single_data_size;
    }

    ret = ip_message_tx_ready(ip_msg, NULL);
    if(ret < 0)
        goto free_ip_msg_quit;

    ret = ip_tx(pcb->netdev, ip_msg, &pcb->idx, pcb->gw_addr);
    if(ret < 0)
        return ret;
    eh_timer_restart(eh_signal_to_custom_event(&pcb->signal_timeout));
    
    ret = pcb->seq++;
    return ret;
free_ip_msg_quit:
    ip_message_free(ip_msg);
    return ret;
}


bool ehip_ping_has_active_request(ping_pcb_t _pcb){
    struct ping_pcb *pcb = (struct ping_pcb *)_pcb;
    return eh_timer_is_running(eh_signal_to_custom_event(&pcb->signal_timeout));
}

static int __init  ping_init(void){
    ping_pcb_pool = eh_mem_pool_create(EHIP_POOL_BASE_ALIGN, sizeof(struct ping_pcb), EHIP_PING_PCB_NUM);
    return eh_ptr_to_error(ping_pcb_pool);
}

static void __exit ping_exit(void){
    eh_mem_pool_destroy(ping_pcb_pool);
}


ehip_protocol_module_export(ping_init, ping_exit);


