/**
 * @file ip_message.c
 * @brief 
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-12-21
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */


#include <stdint.h>
#include <string.h>

#include <eh_error.h>
#include <eh_swab.h>
#include <eh_mem_pool.h>
#include <eh_types.h>
#include <eh_debug.h>
#include <eh_llist.h>

#include <ehip_netdev.h>
#include <ehip_buffer.h>
#include <ehip_module.h>
#include <ehip_chksum.h>
#include <ehip_netdev_trait.h>
#include <ehip-ipv4/ip.h>
#include <ehip-ipv4/ip_message.h>
#include <ehip-mac/hw_addr.h>
#include <ehip-mac/loopback.h>

eh_static_assert(EHIP_IP_MAX_FRAGMENT_NUM <= 0xFF, "IP fragment number must be less than 0xFF.");

#ifndef EH_DBG_MODULE_LEVEL_RX_FRAGMENT
#define EH_DBG_MODULE_LEVEL_RX_FRAGMENT EH_DBG_WARNING
#endif

static eh_mem_pool_t ip_message_pool;
// static eh_mem_pool_t ip_rx_fragment_pool;
// static eh_mem_pool_t ip_tx_fragment_pool;
static eh_mem_pool_t options_bytes_pool;
static uint16_t ip_message_id = 0;

static uint16_be_t get_ip_message_id(void){
    uint16_be_t id = ip_message_id++;
    return eh_hton16(id);
}

static void ip_message_clean_fragment(struct ip_message *msg){
    struct eh_llist_node *pos;
    ehip_buffer_t *netdev_buffer;
    while((pos = eh_llist_dequeue(&msg->buffer_head))){
        netdev_buffer = eh_llist_entry(pos, ehip_buffer_t, node);
        ehip_buffer_free(netdev_buffer);
    }
}

void ip_message_free(struct ip_message *msg){
    ip_message_clean_fragment(msg);
    if(msg->options_bytes)
        eh_mem_pool_free(options_bytes_pool, msg->options_bytes);
    eh_mem_pool_free(ip_message_pool, msg);
}


struct ip_message* ip_message_tx_new(ehip_netdev_t *netdev, uint8_t tos,
    uint8_t ttl, uint8_t protocol, ipv4_addr_t src_addr, ipv4_addr_t dst_addr, 
    uint8_t *options_bytes, ehip_buffer_size_t options_bytes_size, uint8_t header_reserved_size, 
    enum route_table_type route_type ){
    struct ip_message * new_msg;
    void *ret;

    if(netdev == NULL || (options_bytes && options_bytes_size > IP_OPTIONS_MAX_LEN) ){
        return eh_error_to_ptr(EH_RET_INVALID_PARAM);
    }
    new_msg =  eh_mem_pool_alloc(ip_message_pool);
    if(new_msg == NULL)
        return eh_error_to_ptr(EH_RET_MEM_POOL_EMPTY);
    memset(new_msg, 0, sizeof(struct ip_message));
    new_msg->ip_hdr.tos = tos;
    new_msg->ip_hdr.ttl = ttl;
    new_msg->ip_hdr.protocol = protocol;
    new_msg->ip_hdr.src_addr = src_addr;
    new_msg->ip_hdr.dst_addr = dst_addr;
    new_msg->ip_hdr.ihl = 0xF & ((sizeof(struct ip_hdr) + options_bytes_size + 3) >> 2);

    new_msg->tx_header_size = header_reserved_size;
    new_msg->route_type = (uint8_t)route_type;

    if(options_bytes && options_bytes_size > 0){
        new_msg->options_bytes = eh_mem_pool_alloc(options_bytes_pool);
        if(new_msg->options_bytes == NULL){
            ret = eh_error_to_ptr(EH_RET_MEM_POOL_EMPTY);
            goto options_bytes_pool_eh_mem_pool_alloc_error;
        }
        memcpy(new_msg->options_bytes, options_bytes, options_bytes_size);
    }
    eh_llist_head_init(&new_msg->buffer_head);

    if(route_type == ROUTE_TABLE_LOCAL || route_type == ROUTE_TABLE_LOCAL_SELF){
        new_msg->netdev = loopback_default_netdev();
    }else{
        new_msg->netdev = netdev;
    }
    new_msg->flags |= IP_MESSAGE_FLAG_TX;

    return new_msg;
options_bytes_pool_eh_mem_pool_alloc_error:
eh_mem_pool_free(ip_message_pool, new_msg);
    return ret;
}


int ip_message_tx_add_buffer(struct ip_message* msg_hander, ehip_buffer_t** out_buffer){
    ehip_netdev_t *netdev = msg_hander->netdev;
    ehip_buffer_t *buffer, *last_buffer;
    ehip_buffer_size_t last_buffer_payload_tail_residue, limit_size;
    eh_param_assert(msg_hander);
    eh_param_assert(out_buffer);
    eh_param_assert(ip_message_flag_is_tx(msg_hander));
    eh_param_assert(!ip_message_flag_is_ready(msg_hander));

    if(eh_llist_empty(&msg_hander->buffer_head)){
        /* 第一块分片需要添加 tx_header_size */
        buffer = ehip_buffer_limit_new(netdev->attr.buffer_type, 
            (ehip_buffer_size_t)(netdev->attr.hw_head_size + ipv4_hdr_len(&msg_hander->ip_hdr)) +
            (ehip_buffer_size_t)msg_hander->tx_header_size, netdev->attr.mtu + netdev->attr.hw_head_size);
        if(eh_ptr_to_error(buffer) < 0)
            return eh_ptr_to_error(buffer);
        buffer->netdev = netdev;
        eh_llist_add_tail(&buffer->node, &msg_hander->buffer_head);
        *out_buffer = buffer;
        return EH_RET_OK;
    }
    last_buffer = eh_llist_entry_safe(eh_llist_last(&msg_hander->buffer_head),ehip_buffer_t, node);

    /* 查看上一个的buffer 是否还有空闲位置，若有则返回上一次的buffer */
    if(ehip_buffer_get_free_capacity(last_buffer)){
        *out_buffer = last_buffer;
        return EH_RET_OK;
    }
    limit_size = (ehip_buffer_size_t)(((netdev->attr.mtu - ipv4_hdr_len(&msg_hander->ip_hdr)) & (~0x7)) + 
            ipv4_hdr_len(&msg_hander->ip_hdr) + netdev->attr.hw_head_size);
    buffer = ehip_buffer_limit_new(netdev->attr.buffer_type, 
        netdev->attr.hw_head_size + sizeof(struct ip_hdr), limit_size);
    if(eh_ptr_to_error(buffer))
        return eh_ptr_to_error(buffer);

    /* 
     * 如果我们是第二个buffer,那么需要判断第一个buffer是否对齐到8字节边界,如果没有对齐到边界，
     * 我们需要将多余的字节拷贝到第二个buffer
     */
    if(msg_hander->buffer_head.first == msg_hander->buffer_head.last){
        msg_hander->flags |= IP_MESSAGE_FLAG_FRAGMENT;
        last_buffer_payload_tail_residue = (ehip_buffer_get_payload_size(last_buffer) + msg_hander->tx_header_size) & (ehip_buffer_size_t)(0x7);
        if(last_buffer_payload_tail_residue){
            uint8_t* tail_residue = ehip_buffer_payload_tail_reduce(last_buffer, last_buffer_payload_tail_residue);
            uint8_t* dts_payload_ptr = ehip_buffer_payload_tail_append(buffer, last_buffer_payload_tail_residue);
            memcpy(dts_payload_ptr, tail_residue, last_buffer_payload_tail_residue);
        }
    }

    buffer->netdev = netdev;
    eh_llist_add_tail(&buffer->node, &msg_hander->buffer_head);
    *out_buffer = buffer;
    return EH_RET_OK;
}


int ip_message_tx_ready(struct ip_message *msg_hander, const uint8_t *head_data){
    ehip_buffer_t *buffer;
    uint8_t *header_data_buffer = NULL;
    struct ip_hdr * ip_hdr_buffer;
    ehip_buffer_size_t options_len;
    ehip_buffer_size_t offset;
    ehip_buffer_size_t playload_size;

    eh_param_assert(msg_hander);
    eh_param_assert(ip_message_flag_is_tx(msg_hander));
    eh_param_assert(!ip_message_flag_is_ready(msg_hander));
    eh_param_assert(!eh_llist_empty(&msg_hander->buffer_head));

    if(msg_hander->buffer_head.first == msg_hander->buffer_head.last){
        /* 没有进行分片 */
        buffer = eh_llist_entry(eh_llist_first(&msg_hander->buffer_head), ehip_buffer_t, node);
        /* 填充上层（udp/tcp/icmp/igmp等）的头部数据 */
        if( msg_hander->tx_header_size ){
            header_data_buffer = ehip_buffer_payload_head_append(buffer, msg_hander->tx_header_size);
            if(header_data_buffer == NULL)
                return EH_RET_INVALID_STATE;
            if(head_data){
                memcpy(header_data_buffer, head_data, msg_hander->tx_header_size);
            }else{
                memset(header_data_buffer, 0, msg_hander->tx_header_size);
            }
        }

        msg_hander->ip_hdr.version = 4;
        msg_hander->ip_hdr.id = get_ip_message_id();
        msg_hander->ip_hdr.tot_len = eh_hton16(ehip_buffer_get_payload_size(buffer) + ipv4_hdr_len(&msg_hander->ip_hdr));
        msg_hander->ip_hdr.frag_off = 0;
        msg_hander->ip_hdr.check = 0;

        /* 填充ip头部数据 */
        ip_hdr_buffer = (struct ip_hdr *)ehip_buffer_payload_head_append(buffer, ipv4_hdr_len(&msg_hander->ip_hdr));
        if(ip_hdr_buffer == NULL)
            return EH_RET_INVALID_STATE;
        memcpy(ip_hdr_buffer, &msg_hander->ip_hdr, sizeof(struct ip_hdr));
        options_len = ipv4_hdr_len(&msg_hander->ip_hdr) - (ehip_buffer_size_t)sizeof(struct ip_hdr);
        if(options_len && msg_hander->options_bytes)
            memcpy(ip_hdr_buffer->options, msg_hander->options_bytes, options_len);
        if(!loopback_is_loopback_netdev(buffer->netdev))
            ip_hdr_buffer->check = ehip_inet_chksum(ip_hdr_buffer, ipv4_hdr_len(&msg_hander->ip_hdr));

        msg_hander->flags |= IP_MESSAGE_FLAG_READY;
        return EH_RET_OK;
    }

    msg_hander->ip_hdr.version = 4;
    msg_hander->ip_hdr.id = get_ip_message_id();
    msg_hander->ip_hdr.frag_off = 0;
    offset = 0;

    /* 填充上层（udp/tcp/icmp/igmp等）的头部数据 */
    if( msg_hander->tx_header_size ){
        buffer = eh_llist_entry(eh_llist_first(&msg_hander->buffer_head), ehip_buffer_t, node);
        header_data_buffer = ehip_buffer_payload_head_append(buffer, msg_hander->tx_header_size);
        if(header_data_buffer == NULL)
            return EH_RET_INVALID_STATE;
        if(head_data){
            memcpy(header_data_buffer, head_data, msg_hander->tx_header_size);
        }else{
            memset(header_data_buffer, 0, msg_hander->tx_header_size);
        }
    }
    
    
    eh_llist_for_each_entry(buffer, &msg_hander->buffer_head, node){
        playload_size = ehip_buffer_get_payload_size(buffer);
        if(buffer->node.next == NULL){
            ipv4_hdr_frag_set(&msg_hander->ip_hdr, offset, 0);
        }else{
            if(playload_size & 0x7)
                return EH_RET_INVALID_STATE;
            ipv4_hdr_frag_set(&msg_hander->ip_hdr, offset, IP_FRAG_MF);
        }

        offset += playload_size;
        msg_hander->ip_hdr.tot_len = eh_hton16( playload_size + ipv4_hdr_len(&msg_hander->ip_hdr) );
        msg_hander->ip_hdr.check = 0;
        
        ip_hdr_buffer = (struct ip_hdr *)ehip_buffer_payload_head_append(
                buffer, ipv4_hdr_len(&msg_hander->ip_hdr));
        if(ip_hdr_buffer == NULL)
            return EH_RET_INVALID_STATE;
        memcpy(ip_hdr_buffer, &msg_hander->ip_hdr, sizeof(struct ip_hdr));
        options_len = ipv4_hdr_len(&msg_hander->ip_hdr) - (ehip_buffer_size_t)sizeof(struct ip_hdr);
        if(options_len){
            if(msg_hander->options_bytes)
                memcpy(ip_hdr_buffer->options, msg_hander->options_bytes, options_len);

            msg_hander->ip_hdr.ihl = sizeof(struct ip_hdr) >> 2;
        }
        if(!loopback_is_loopback_netdev(buffer->netdev))
            ip_hdr_buffer->check = ehip_inet_chksum(ip_hdr_buffer, ipv4_hdr_len(ip_hdr_buffer));

    }
    msg_hander->flags |= IP_MESSAGE_FLAG_READY;
    return EH_RET_OK;
}



int ip_message_rx_add_fragment(struct ip_message *fragment_message, ehip_buffer_t *buffer, const struct ip_hdr *ip_hdr){
    uint16_t fragment_start_offset;
    uint16_t fragment_end_offset;
    uint16_t fragment_check_offset;
    int  ret;
    struct eh_llist_node *prev, *pos, *next;
    ehip_buffer_t *buffer_pos;

    if( !ip_message_flag_is_fragment(fragment_message) ){
        ret = EH_RET_INVALID_PARAM;
        goto drop;
    }
    
    if(ip_message_flag_is_broken(fragment_message)){
        fragment_message->rx_fragment_expires_cd = EHIP_IP_FRAGMENT_TIMEOUT/2;
        ret = EH_RET_OK;
        goto drop;
    }
    
    fragment_start_offset = ipv4_hdr_offset(ip_hdr);
    fragment_end_offset = (uint16_t)(ipv4_hdr_offset(ip_hdr) + ipv4_hdr_body_len(ip_hdr));

    if(ipv4_hdr_is_mf(ip_hdr)){
        /* 
         * 中间的分片必须以8字对齐 
         * 或者分片数量达到最大值时还没有得到最后一块分片
         */
        if( ipv4_hdr_body_len(ip_hdr) & 0x7 ){
            /* ip中间的分片没有向8字节对齐 */
            eh_msysfl(RX_FRAGMENT,"Ip fragment not align 8.");
            ret = EH_RET_INVALID_STATE;
            goto drop;
        }

        if(fragment_message->ip_hdr.tot_len == 0 && (int)fragment_message->rx_fragment_cnt + 1 >= (int)EHIP_IP_MAX_FRAGMENT_NUM){
            /* 
             * 如果分片数量达到最大值时还没有得到最后一块分片
             * 那么就不再接收新的分片
             */
            eh_msysfl(RX_FRAGMENT,"Ip fragment max.");
            ip_message_clean_fragment(fragment_message);
            fragment_message->flags |= IP_MESSAGE_FLAG_BROKEN;
            fragment_message->rx_fragment_expires_cd = EHIP_IP_FRAGMENT_TIMEOUT/2;
            ret = EH_RET_OK;
            goto drop;
        }
    }else{
        /* 最后一个分片报文 */
        if( fragment_message->ip_hdr.tot_len ){
            /* 重复接收到最后一片报文 */
            eh_msysfl(RX_FRAGMENT,"Ip fragment repeat.");
            ret = EH_RET_OK;
            goto drop;
        }
        fragment_message->ip_hdr.tot_len = 
            (uint16_be_t)(ipv4_hdr_offset(ip_hdr) + ipv4_hdr_body_len(ip_hdr));
    }
    buffer->ip_rx.fragment_start_offset = fragment_start_offset;
    buffer->ip_rx.fragment_end_offset = fragment_end_offset;

    /* 大部分情况下，应该都进入尾插法的分支 */
    buffer_pos = eh_llist_entry_safe(eh_llist_last(&fragment_message->buffer_head), ehip_buffer_t, node);
    if(buffer_pos == NULL || eh_likely(buffer_pos->ip_rx.fragment_end_offset <= buffer->ip_rx.fragment_start_offset)){
        if(fragment_message->ip_hdr.tot_len && buffer->ip_rx.fragment_end_offset > fragment_message->ip_hdr.tot_len){
            ip_message_clean_fragment(fragment_message);
            fragment_message->flags |= IP_MESSAGE_FLAG_BROKEN;
            fragment_message->rx_fragment_expires_cd = EHIP_IP_FRAGMENT_TIMEOUT/2;
            ret = EH_RET_OK;
            goto drop;
        }
        eh_llist_add_tail(&buffer->node, &fragment_message->buffer_head);
        goto check_finish;
    }
    /* 从头开始找到合适的位置插入 */
    eh_mdebugfl(RX_FRAGMENT,"Ip fragment insert. start_offset:%u, end_offset:%u",
        buffer->ip_rx.fragment_start_offset, buffer->ip_rx.fragment_end_offset);
    eh_llist_for_each_safe(prev, pos, next, &fragment_message->buffer_head){
        buffer_pos = eh_llist_entry(pos, ehip_buffer_t, node);
        if( buffer->ip_rx.fragment_end_offset <= buffer_pos->ip_rx.fragment_start_offset){
            eh_llist_insert(prev, &buffer->node, &fragment_message->buffer_head);
            goto check_finish;
        }
        if( buffer->ip_rx.fragment_start_offset < buffer_pos->ip_rx.fragment_end_offset){
            eh_msysfl(RX_FRAGMENT,"Ip fragment repeat.");
            ret = EH_RET_OK;
            goto drop;
        }
    }
check_finish:
    fragment_message->rx_fragment_cnt++;
    /* 插入成功后，检查是否已经拿到了尾部，若拿到了尾部，则进行完整性检测*/
    if(fragment_message->ip_hdr.tot_len == 0)
        return 0;
    fragment_check_offset = 0;
    eh_llist_for_each_entry(buffer_pos, &fragment_message->buffer_head, node){
        if(fragment_check_offset != buffer_pos->ip_rx.fragment_start_offset)
            return 0;
        fragment_check_offset = buffer_pos->ip_rx.fragment_end_offset;
    }
    /* tot_len中存储着rx报文的整体大小 */
    fragment_message->flags |= IP_MESSAGE_FLAG_READY;
    return FRAGMENT_REASSEMBLY_FINISH;
drop:
    ehip_buffer_free(buffer);
    return ret;
}

static struct ip_message* _ip_message_rx_new(const struct ip_hdr *ip_hdr){
    struct ip_message * new_msg =  eh_mem_pool_alloc(ip_message_pool);
    if(new_msg == NULL)
        return NULL;
    memset(new_msg, 0, sizeof(struct ip_message));
    if(ip_hdr->ihl > 5){
        new_msg->options_bytes = eh_mem_pool_alloc(options_bytes_pool);
        if(new_msg->options_bytes == NULL){
            eh_mem_pool_free(ip_message_pool, new_msg);
            return NULL;
        }
        memcpy(new_msg->options_bytes, ip_hdr->options, (size_t)((ip_hdr->ihl - 5) * 4));
    }
    memcpy(&new_msg->ip_hdr, ip_hdr, sizeof(struct ip_hdr));
    return new_msg;
}
struct ip_message* ip_message_rx_new_fragment(ehip_netdev_t *netdev, const struct ip_hdr *ip_hdr, enum route_table_type route_type){
    struct ip_message * new_msg = _ip_message_rx_new(ip_hdr);
    if(new_msg == NULL)
        return eh_error_to_ptr(EH_RET_MEM_POOL_EMPTY);
    new_msg->flags |= IP_MESSAGE_FLAG_FRAGMENT;
    new_msg->ip_hdr.tot_len = 0;
    new_msg->rx_fragment_expires_cd = EHIP_IP_FRAGMENT_TIMEOUT;
    new_msg->route_type = (uint8_t)route_type;
    new_msg->rx_fragment_cnt = 1;
    new_msg->netdev = netdev;
    return new_msg;
}

struct ip_message* ip_message_rx_new(ehip_netdev_t *netdev, ehip_buffer_t *buffer, const struct ip_hdr *ip_hdr, enum route_table_type route_type){
    struct ip_message * new_msg = _ip_message_rx_new(ip_hdr);
    if(new_msg == NULL){
        ehip_buffer_free(buffer);
        return eh_error_to_ptr(EH_RET_MEM_POOL_EMPTY);
    }
    /* 此时该字段存储ip报文的总长度，不包含ip头 */
    new_msg->ip_hdr.tot_len = ipv4_hdr_body_len(ip_hdr);
    eh_llist_add_tail(&buffer->node, &new_msg->buffer_head);
    new_msg->route_type = (uint8_t)route_type;
    new_msg->flags |= IP_MESSAGE_FLAG_READY;
    new_msg->netdev = netdev;
    return new_msg;
}


int  ip_message_rx_data_size(struct ip_message *msg_hander){
    eh_param_assert(msg_hander);
    eh_param_assert(ip_message_flag_is_ready(msg_hander));
    eh_param_assert(ip_message_flag_is_rx(msg_hander));
    return  msg_hander->ip_hdr.tot_len;
}


int ip_message_rx_data_tail_trim(struct ip_message *msg_hander, ehip_buffer_size_t size){
    ehip_buffer_size_t tot_size;
    ehip_buffer_t *buffer_pos;
    ehip_buffer_size_t fragment_size;
    ehip_buffer_size_t trim_offset_start;
    ehip_buffer_size_t trim_size;
    struct eh_llist_node *prev, *pos, *next;
    ehip_buffer_t *last_buffer;
    struct eh_llist_head     tmp_buffer_head;
    eh_param_assert(msg_hander);
    eh_param_assert(ip_message_flag_is_ready(msg_hander));
    eh_param_assert(ip_message_flag_is_rx(msg_hander));

    eh_llist_head_init(&tmp_buffer_head);

    tot_size = msg_hander->ip_hdr.tot_len;
    if(tot_size < size)
        return EH_RET_INVALID_PARAM;
    
    last_buffer = eh_llist_entry(eh_llist_last(&msg_hander->buffer_head), ehip_buffer_t, node);
    if(ehip_buffer_get_payload_size(last_buffer) > size){
        ehip_buffer_payload_tail_reduce(last_buffer, size);
        tot_size -= size;
        goto finish;
    }
    trim_offset_start = tot_size - size;
    eh_llist_for_each_safe(prev, pos, next, &msg_hander->buffer_head){
        buffer_pos = eh_llist_entry(pos, ehip_buffer_t, node);
        fragment_size = ehip_buffer_get_payload_size(buffer_pos);
        if(fragment_size == 0)
            break;
        if(trim_offset_start >= fragment_size){
            trim_offset_start -= fragment_size;
            continue;
        }
        if(trim_offset_start == 0){
            tot_size -= fragment_size;
            eh_llist_del_node_in_for_each_safe(&msg_hander->buffer_head, prev, next);
            ehip_buffer_payload_tail_reduce(buffer_pos, fragment_size);
            eh_llist_add_tail(&buffer_pos->node, &tmp_buffer_head);
            continue;
        }
        /* 开始修剪 */
        trim_size = fragment_size - trim_offset_start;
        ehip_buffer_payload_tail_reduce(buffer_pos, trim_size);
        tot_size -= trim_size;
        trim_offset_start = 0;
    }
finish:
    if(!eh_llist_empty(&tmp_buffer_head))
        eh_llist_add_batch_tail(eh_llist_first(&tmp_buffer_head), eh_llist_last(&tmp_buffer_head), &msg_hander->buffer_head);
    msg_hander->ip_hdr.tot_len = tot_size;
    return 0;
}

int _ip_message_rx_read_advanced(struct ip_message *msg_hander, uint8_t **out_data, 
    ehip_buffer_size_t size, uint8_t *out_standby_buffer, enum _ip_message_read_advanced_type type){
    ehip_buffer_size_t       single_max_read_size = 0;
    ehip_buffer_size_t       rl = 0;
    struct eh_llist_node    *prev, *pos, *next;
    ehip_buffer_t           *buffer_pos;
    uint8_t                 *write_data_ptr;
    struct eh_llist_head     tmp_buffer_head;

    eh_param_assert(msg_hander);
    eh_param_assert(out_data);
    eh_param_assert(ip_message_flag_is_rx(msg_hander));
    eh_param_assert(type < IP_MESSAGE_READ_ADVANCED_MAX);
    if(type == IP_MESSAGE_READ_ADVANCED_REAL_COPY_READ)
        eh_param_assert(out_standby_buffer);
    eh_llist_head_init(&tmp_buffer_head);

    if(type == IP_MESSAGE_READ_ADVANCED_TYPE_SMART_READ || type == IP_MESSAGE_READ_ADVANCED_ZERO_COPY_READ){
        ehip_buffer_size_t buffer_payload_size = 0;
        buffer_pos = eh_llist_entry(eh_llist_first(&msg_hander->buffer_head), ehip_buffer_t, node);
        buffer_payload_size = ehip_buffer_get_payload_size(buffer_pos);
        if(type == IP_MESSAGE_READ_ADVANCED_ZERO_COPY_READ || size == buffer_payload_size){
            *out_data = ehip_buffer_payload_head_reduce(buffer_pos, buffer_payload_size);
            eh_llist_dequeue(&msg_hander->buffer_head);
            eh_llist_add_tail(&buffer_pos->node, &tmp_buffer_head);
            rl = buffer_payload_size;
            goto finish;
        }
        /* 智能判断 */
        if(size < buffer_payload_size){
            *out_data = ehip_buffer_payload_head_reduce(buffer_pos, size);
            rl = size;
            goto finish;
        }
    }

    /* 需要拷贝的情况 */
    *out_data = out_standby_buffer;
    if(type == IP_MESSAGE_READ_ADVANCED_TYPE_SMART_READ)
        eh_param_assert(out_standby_buffer);

    write_data_ptr = out_standby_buffer;
    eh_llist_for_each_safe(prev, pos, next, &msg_hander->buffer_head){
        buffer_pos = eh_llist_entry(pos, ehip_buffer_t, node);
        single_max_read_size = ehip_buffer_get_payload_size(buffer_pos) > size ? 
            size : ehip_buffer_get_payload_size(buffer_pos);
        if(single_max_read_size == 0)
            break;
        size -= single_max_read_size;
        memcpy(write_data_ptr, ehip_buffer_payload_head_reduce(buffer_pos, single_max_read_size), single_max_read_size);
        write_data_ptr += single_max_read_size;
        if(ehip_buffer_get_payload_size(buffer_pos) == 0){
            /* 放到结尾 */
            eh_llist_del_node_in_for_each_safe(&msg_hander->buffer_head, prev, next);
            eh_llist_add_tail(&buffer_pos->node, &tmp_buffer_head);
        }
    }
    rl = (ehip_buffer_size_t)(write_data_ptr - out_standby_buffer);
finish:
    if(!eh_llist_empty(&tmp_buffer_head))
        eh_llist_add_batch_tail(eh_llist_first(&tmp_buffer_head), eh_llist_last(&tmp_buffer_head), &msg_hander->buffer_head);
    msg_hander->ip_hdr.tot_len -= rl;
    return rl;
}


int ip_message_rx_read_skip(struct ip_message *msg, ehip_buffer_size_t size){
    eh_param_assert(msg);
    struct eh_llist_node    *prev, *pos, *next;
    ehip_buffer_t           *buffer_pos;
    struct eh_llist_head     tmp_buffer_head;
    ehip_buffer_size_t       single_max_read_size = 0;
    ehip_buffer_size_t       rl = 0;

    eh_llist_head_init(&tmp_buffer_head);

    eh_llist_for_each_safe(prev, pos, next, &msg->buffer_head){
        buffer_pos = eh_llist_entry(pos, ehip_buffer_t, node);
        single_max_read_size = ehip_buffer_get_payload_size(buffer_pos) > size ? 
            size : ehip_buffer_get_payload_size(buffer_pos);
        if(single_max_read_size == 0)
            break;
        rl += single_max_read_size;
        size -= single_max_read_size;
        ehip_buffer_payload_head_reduce(buffer_pos, single_max_read_size);
        if(ehip_buffer_get_payload_size(buffer_pos) == 0){
            eh_llist_del_node_in_for_each_safe(&msg->buffer_head, prev, next);
            eh_llist_add_tail(&buffer_pos->node, &tmp_buffer_head);
        }
    }
    if(!eh_llist_empty(&tmp_buffer_head))
        eh_llist_add_batch_tail(eh_llist_first(&tmp_buffer_head), eh_llist_last(&tmp_buffer_head), &msg->buffer_head);
    msg->ip_hdr.tot_len -= rl;
    return rl;
}

struct ip_message *ip_message_rx_ref_dup(struct ip_message *msg){
    struct ip_message * new_msg;
    ehip_buffer_t           *buffer_pos;

    if(ip_message_flag_is_tx(msg))
        return NULL;

    new_msg = eh_mem_pool_alloc(ip_message_pool);
    if(new_msg == NULL)
        return NULL;
    memcpy(new_msg, msg, sizeof(struct ip_message));
    
    eh_llist_head_init(&new_msg->buffer_head);
    /* 复制选项字节内容 */
    if(msg->options_bytes){
        new_msg->options_bytes = eh_mem_pool_alloc(options_bytes_pool);
        if(new_msg->options_bytes == NULL)
            goto error;
        memcpy(new_msg->options_bytes, msg->options_bytes, IP_OPTIONS_MAX_LEN);
    }
    eh_llist_for_each_entry(buffer_pos, &msg->buffer_head, node){
        ehip_buffer_t *new_buffer_pos = ehip_buffer_ref_dup(buffer_pos);
        if(new_buffer_pos == NULL)
            goto error;
        eh_llist_add_tail(&new_buffer_pos->node, &new_msg->buffer_head);
    }
    return new_msg;
error:
    ip_message_free(new_msg);
    return eh_error_to_ptr(EH_RET_MEM_POOL_EMPTY);
}


static int __init ip_message_pool_init(void)
{
    int ret;
    ip_message_pool = eh_mem_pool_create(EHIP_POOL_BASE_ALIGN, sizeof(struct ip_message), EHIP_IP_MAX_BUFFER_NUM);
    if((ret = eh_ptr_to_error(ip_message_pool)) < 0 ){
        return ret;
    }
    options_bytes_pool = eh_mem_pool_create(EHIP_POOL_BASE_ALIGN, IP_OPTIONS_MAX_LEN, EHIP_IP_MAX_IP_OPTIONS_BYTES_BUFFER_NUM);
    if((ret = eh_ptr_to_error(options_bytes_pool)) < 0 ){
        goto options_bytes_pool_err;
    }
    return 0;
options_bytes_pool_err:
    eh_mem_pool_destroy(ip_message_pool);
    return ret;
}

static void __exit ip_message_pool_exit(void)
{
    eh_mem_pool_destroy(options_bytes_pool);
    eh_mem_pool_destroy(ip_message_pool);
}

ehip_preinit_module_export(ip_message_pool_init, ip_message_pool_exit);
