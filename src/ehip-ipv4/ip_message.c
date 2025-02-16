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

#include <ehip_netdev.h>
#include <ehip_buffer.h>
#include <ehip_module.h>
#include <ehip_chksum.h>
#include <ehip_netdev_trait.h>
#include <ehip-ipv4/ip.h>
#include <ehip-ipv4/ip_message.h>
#include <ehip-mac/hw_addr.h>

eh_static_assert(EHIP_IP_MAX_FRAGMENT_NUM <= 0xFF, "IP fragment number must be less than 0xFF.");

static eh_mem_pool_t ip_message_pool;
static eh_mem_pool_t ip_rx_fragment_pool;
static eh_mem_pool_t ip_tx_fragment_pool;
static eh_mem_pool_t options_bytes_pool;
static uint16_t ip_message_id = 0;

static uint16_be_t get_ip_message_id(void){
    uint16_be_t id = ip_message_id++;
    return eh_hton16(id);
}

static void ip_message_fragment_boroken(struct ip_message *msg){
    int i, sort_i;
    ehip_buffer_t *pos_buffer;
    if(ip_message_flag_is_tx(msg)){
        /* TODO */
    }else{
        ip_message_rx_fragment_for_each(pos_buffer, i, sort_i, msg){
            ehip_buffer_free(pos_buffer);
        }
    }
    msg->flags |= IP_MESSAGE_FLAG_BROKEN;
    msg->rx_fragment->fragment_cnt = 0;
}

void ip_message_free(struct ip_message *msg){
    if(ip_message_flag_is_fragment(msg)){
        int i, sort_i;
        ehip_buffer_t *pos_buffer;
        if(ip_message_flag_is_tx(msg)){
            ip_message_tx_fragment_for_each(pos_buffer, i, msg){
                ehip_buffer_free(pos_buffer);
            }
            eh_mem_pool_free(ip_tx_fragment_pool, msg->tx_fragment);
        }else{
            ip_message_rx_fragment_for_each(pos_buffer, i, sort_i, msg){
                ehip_buffer_free(pos_buffer);
            }
            eh_mem_pool_free(ip_rx_fragment_pool, msg->rx_fragment);
        }
    }else{
        if(msg->buffer && ( !ip_message_flag_is_tx(msg) || ip_message_flag_is_tx_buffer_init(msg)))
            ehip_buffer_free(msg->buffer);
    }
    eh_mem_pool_free(ip_message_pool, msg);
}


struct ip_message* ip_message_tx_new(ehip_netdev_t *netdev, uint8_t tos,
    uint8_t ttl, uint8_t protocol, ipv4_addr_t src_addr, ipv4_addr_t dst_addr, 
    uint8_t *options_bytes, ehip_buffer_size_t options_bytes_size){
    struct ip_message * new_msg;

    if(netdev == NULL || (options_bytes && options_bytes_size > IP_OPTIONS_MAX_LEN) ){
        return NULL;
    }
    new_msg =  eh_mem_pool_alloc(ip_message_pool);
    if(new_msg == NULL)
        return NULL;
    memset(new_msg, 0, sizeof(struct ip_message));
    new_msg->flags |= IP_MESSAGE_FLAG_TX;
    new_msg->ip_hdr.tos = tos;
    new_msg->ip_hdr.ttl = ttl;
    new_msg->ip_hdr.protocol = protocol;
    new_msg->ip_hdr.src_addr = src_addr;
    new_msg->ip_hdr.dst_addr = dst_addr;
    new_msg->ip_hdr.ihl = 0xF & ((sizeof(struct ip_hdr) + options_bytes_size + 3) >> 2);

    new_msg->tx_init_netdev = netdev;

    if(options_bytes && options_bytes_size > 0){
        new_msg->options_bytes = eh_mem_pool_alloc(options_bytes_pool);
        if(new_msg->options_bytes == NULL){
            goto options_bytes_pool_eh_mem_pool_alloc_error;
        }
        memcpy(new_msg->options_bytes, options_bytes, options_bytes_size);
    }

    return new_msg;
options_bytes_pool_eh_mem_pool_alloc_error:
eh_mem_pool_free(ip_message_pool, new_msg);
    return NULL;
}


int ip_message_tx_add_buffer(struct ip_message* msg_hander, ehip_buffer_t** out_buffer, ehip_buffer_size_t *out_buffer_capacity_size){
    ehip_netdev_t *netdev;
    ehip_buffer_t *buffer;
    struct ip_tx_fragment *tx_fragment;
    eh_param_assert(msg_hander);
    eh_param_assert(out_buffer);
    eh_param_assert(out_buffer_capacity_size);
    eh_param_assert(ip_message_flag_is_tx(msg_hander));

    if(!ip_message_flag_is_fragment(msg_hander)){
        /* 没有进行分片 */
        if(!ip_message_flag_is_tx_buffer_init(msg_hander)){
            netdev = msg_hander->tx_init_netdev;
            buffer = ehip_buffer_new(netdev->attr.buffer_type, netdev->attr.hw_head_size + ipv4_hdr_len(&msg_hander->ip_hdr));
            if(eh_ptr_to_error(buffer) < 0)
                return eh_ptr_to_error(buffer);
            msg_hander->buffer = buffer;
            msg_hander->flags |= IP_MESSAGE_FLAG_TX_BUFFER_INIT;
            msg_hander->buffer->netdev = netdev;
            *out_buffer = buffer;
            *out_buffer_capacity_size = netdev->attr.mtu - ipv4_hdr_len(&msg_hander->ip_hdr);
            return EH_RET_OK;
        }
        /* 修改其为分片模式 */
        tx_fragment = eh_mem_pool_alloc(ip_tx_fragment_pool);
        if(tx_fragment == NULL)
            return EH_RET_MEM_POOL_EMPTY;
        tx_fragment->fragment_read_offset = 0;
        tx_fragment->fragment_add_offset = 1;
        tx_fragment->fragment_offset = 0;
        tx_fragment->fragment_buffer[0] = msg_hander->buffer;
        msg_hander->tx_fragment = tx_fragment;
        msg_hander->flags |= IP_MESSAGE_FLAG_FRAGMENT;
    }
    /* 分片模式 */
    tx_fragment = msg_hander->tx_fragment;
    if(tx_fragment->fragment_add_offset >= EHIP_IP_MAX_FRAGMENT_NUM)
        return EH_RET_INVALID_STATE;
    netdev = tx_fragment->fragment_buffer[0]->netdev;
    buffer = ehip_buffer_new(netdev->attr.buffer_type, 
        netdev->attr.hw_head_size + sizeof(struct ip_hdr));
    if(eh_ptr_to_error(buffer))
        return eh_ptr_to_error(buffer);
    buffer->netdev = netdev;
    *out_buffer = buffer;
    *out_buffer_capacity_size = (ehip_buffer_size_t)(netdev->attr.mtu - ipv4_hdr_len(&msg_hander->ip_hdr)) & (ehip_buffer_size_t)(~0x7);
    tx_fragment->fragment_buffer[tx_fragment->fragment_add_offset++] = buffer;
    
    return EH_RET_OK;
}


int ip_message_tx_ready(struct ip_message *msg_hander, const ehip_hw_addr_t* dst_hw_addr ){
    ehip_netdev_t *netdev;
    int ret;
    ehip_buffer_t *buffer;
    struct ip_hdr * ip_hdr_buffer;
    ehip_buffer_size_t options_len;
    ehip_buffer_size_t offset;
    ehip_buffer_size_t playload_size;
    struct ip_tx_fragment *tx_fragment;

    eh_param_assert(msg_hander);
    eh_param_assert(ip_message_flag_is_tx(msg_hander));
    eh_param_assert(ip_message_flag_is_tx_buffer_init(msg_hander));
    eh_param_assert(!ip_message_flag_is_tx_ready(msg_hander));

    if(!ip_message_flag_is_fragment(msg_hander)){
        /* 没有进行分片 */
        buffer = msg_hander->buffer;

        netdev = buffer->netdev;

        msg_hander->ip_hdr.version = 4;
        msg_hander->ip_hdr.id = get_ip_message_id();
        msg_hander->ip_hdr.tot_len = eh_hton16(ehip_buffer_get_payload_size(buffer) + ipv4_hdr_len(&msg_hander->ip_hdr));
        msg_hander->ip_hdr.frag_off = 0;
        msg_hander->ip_hdr.check = 0;

        ip_hdr_buffer = (struct ip_hdr *)ehip_buffer_head_append(buffer, ipv4_hdr_len(&msg_hander->ip_hdr));
        if(ip_hdr_buffer == NULL)
            return EH_RET_INVALID_STATE;
        memcpy(ip_hdr_buffer, &msg_hander->ip_hdr, sizeof(struct ip_hdr));
        options_len = ipv4_hdr_len(&msg_hander->ip_hdr) - (ehip_buffer_size_t)sizeof(struct ip_hdr);
        if(options_len && msg_hander->options_bytes)
            memcpy(ip_hdr_buffer->options, msg_hander->options_bytes, options_len);
        ip_hdr_buffer->check = ehip_inet_chksum(ip_hdr_buffer, ipv4_hdr_len(&msg_hander->ip_hdr));

        ret = ehip_netdev_trait_hard_header( netdev, buffer, 
            ehip_netdev_trait_hw_addr(netdev), dst_hw_addr, 
            EHIP_PTYPE_ETHERNET_IP, ehip_buffer_get_payload_size(buffer) );
        if(ret < 0)
            return ret;
        ret = ehip_netdev_trait_buffer_padding(netdev, buffer);
        if(ret < 0)
            return ret;
        msg_hander->flags |= IP_MESSAGE_FLAG_TX_READY;
        return EH_RET_OK;
    }
    /* 分片模式 */
    tx_fragment = msg_hander->tx_fragment;
    if(tx_fragment->fragment_add_offset < 2){
        return EH_RET_INVALID_STATE;
    }

    msg_hander->ip_hdr.version = 4;
    msg_hander->ip_hdr.id = get_ip_message_id();
    msg_hander->ip_hdr.frag_off = 0;
    offset = 0;
    netdev = tx_fragment->fragment_buffer[0]->netdev;
    for(int i = 0; i < tx_fragment->fragment_add_offset; i++){
        buffer = tx_fragment->fragment_buffer[i];
        ipv4_hdr_frag_set(&msg_hander->ip_hdr, offset, 
            i == tx_fragment->fragment_add_offset - 1 ? 0 : IP_FRAG_MF);
        playload_size = ehip_buffer_get_payload_size(buffer);
        if(playload_size & 0x7){
            /* 分片必须以8字节对齐 */
            return EH_RET_INVALID_STATE;
        }
        offset += playload_size;
        msg_hander->ip_hdr.tot_len = eh_hton16( playload_size + ipv4_hdr_len(&msg_hander->ip_hdr) );
        msg_hander->ip_hdr.check = 0;
        
        ip_hdr_buffer = (struct ip_hdr *)ehip_buffer_head_append(
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
        ip_hdr_buffer->check = ehip_inet_chksum(ip_hdr_buffer, ipv4_hdr_len(ip_hdr_buffer));

        ret = ehip_netdev_trait_hard_header( netdev, buffer, 
            ehip_netdev_trait_hw_addr(netdev), dst_hw_addr,
            EHIP_PTYPE_ETHERNET_IP, ehip_buffer_get_payload_size(buffer));
        if(ret < 0)
            return ret;
        ret = ehip_netdev_trait_buffer_padding(netdev, buffer);
        if(ret < 0)
            return ret;
    }
    msg_hander->flags |= IP_MESSAGE_FLAG_TX_READY;
    return EH_RET_OK;
}



int ip_message_rx_merge_fragment(struct ip_message *fragment, ehip_buffer_t *buffer, const struct ip_hdr *ip_hdr){
    uint16_t fragment_start_offset;
    uint16_t fragment_end_offset;
    uint16_t fragment_check_offset;
    struct fragment_info *prev_fragment_msg;
    struct fragment_info *fragment_msg;
    struct ip_rx_fragment *rx_fragment = fragment->rx_fragment;
    int sort_i, ret, install_index;
    

    if( !ip_message_flag_is_fragment(fragment) ){
        ret = EH_RET_INVALID_PARAM;
        goto drop;
    }
    
    if(ip_message_flag_is_broken(fragment)){
        rx_fragment->expires_cd = EHIP_IP_FRAGMENT_TIMEOUT/2;
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
            eh_debugfl("Ip fragment not align 8.");
            ret = EH_RET_INVALID_STATE;
            goto drop;
        }

        if(fragment->ip_hdr.tot_len == 0 && (int)rx_fragment->fragment_cnt + 1 >= (int)EHIP_IP_MAX_FRAGMENT_NUM){
            /* 
             * 如果分片数量达到最大值时还没有得到最后一块分片
             * 那么就不再接收新的分片
             */
            eh_debugfl("Ip fragment max.");
            ip_message_fragment_boroken(fragment);
            rx_fragment->expires_cd = EHIP_IP_FRAGMENT_TIMEOUT/2;
            ret = EH_RET_OK;
            goto drop;
        }
    }else{
        /* 最后一个分片报文 */
        if( fragment->ip_hdr.tot_len ){
            /* 重复接收到最后一片报文 */
            eh_debugfl("Ip fragment repeat.");
            ret = EH_RET_OK;
            goto drop;
        }
        fragment->ip_hdr.tot_len = 
            (uint16_be_t)(ipv4_hdr_offset(ip_hdr) + ipv4_hdr_body_len(ip_hdr));
    }

    rx_fragment->fragment_info[rx_fragment->fragment_cnt].fragment_buffer = buffer;
    rx_fragment->fragment_info[rx_fragment->fragment_cnt].fragment_start_offset = fragment_start_offset;
    rx_fragment->fragment_info[rx_fragment->fragment_cnt].fragment_end_offset = fragment_end_offset;

    prev_fragment_msg = NULL;
    for( install_index = 0; 
            install_index < rx_fragment->fragment_cnt; 
            install_index++, prev_fragment_msg = fragment_msg   ){
        sort_i = rx_fragment->fragment_sort[install_index];
        fragment_msg = rx_fragment->fragment_info + sort_i;

        if( fragment_end_offset > fragment_msg->fragment_start_offset )
            continue;

        if( prev_fragment_msg == NULL || 
            fragment_start_offset < prev_fragment_msg->fragment_end_offset 
        ){
            /* 两片报文出现重叠或者重复 */
            eh_debugfl("Ip fragment repeat.");
            ret = EH_RET_OK;
            goto drop;
        }
        /* 
         * 找到了合适的位置，准备插入，
         * 先整体后移，再插入 
         */
        for(    int j = rx_fragment->fragment_cnt; 
                j > install_index; 
                j-- ){
            rx_fragment->fragment_sort[j] = rx_fragment->fragment_sort[j - 1];
        }
        break;
    }
    rx_fragment->fragment_sort[install_index] = rx_fragment->fragment_cnt;
    rx_fragment->expires_cd = EHIP_IP_FRAGMENT_TIMEOUT;
    rx_fragment->fragment_cnt++;
    /* 插入成功后，检查是否已经拿到了尾部，若拿到了尾部，则进行完整性检测*/
    if(fragment->ip_hdr.tot_len == 0)
        return 0;
    fragment_check_offset = 0;
    for(int i=0; i < rx_fragment->fragment_cnt; i++){
        sort_i = rx_fragment->fragment_sort[i];
        fragment_msg = rx_fragment->fragment_info + sort_i;
        if(fragment_check_offset != fragment_msg->fragment_start_offset)
            return 0;
        fragment_check_offset = fragment_msg->fragment_end_offset;
    }
    fragment->ip_hdr.tot_len = eh_hton16(fragment_check_offset);
    fragment->rx_fragment->fragment_buffer_size = fragment_check_offset;
    return FRAGMENT_REASSE_FINISH;
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

static void _ip_message_rx_free(struct ip_message *msg){
    if(msg->options_bytes)
        eh_mem_pool_free(options_bytes_pool, msg->options_bytes);
    eh_mem_pool_free(ip_message_pool, msg);
}

struct ip_message* ip_message_rx_new(ehip_netdev_t *netdev, ehip_buffer_t *buffer, const struct ip_hdr *ip_hdr){
    (void)netdev;
    struct ip_message * new_msg = _ip_message_rx_new(ip_hdr);
    if(new_msg == NULL){
        ehip_buffer_free(buffer);
        return NULL;
    }
    new_msg->buffer = buffer;
    return new_msg;
}

struct ip_message* ip_message_rx_new_fragment(ehip_netdev_t *netdev, ehip_buffer_t *buffer, const struct ip_hdr *ip_hdr){
    (void)netdev;
    struct ip_message * new_msg = _ip_message_rx_new(ip_hdr);
    if(new_msg == NULL){
        goto ip_message_rx_new_err;
    }
    new_msg->rx_fragment = eh_mem_pool_alloc(ip_rx_fragment_pool);
    if(new_msg->rx_fragment == NULL)
        goto eh_mem_pool_alloc_ip_rx_fragment_fail;
    new_msg->flags |= IP_MESSAGE_FLAG_FRAGMENT;
    if(ipv4_hdr_is_mf(ip_hdr)){
        new_msg->ip_hdr.tot_len = 0;
    }else{
        /* 暂时将此字段作为主机字节序 */
        new_msg->ip_hdr.tot_len = 
            (uint16_be_t)(ipv4_hdr_offset(ip_hdr) + ipv4_hdr_body_len(ip_hdr));
    }
    new_msg->rx_fragment->fragment_cnt = 1;
    new_msg->rx_fragment->fragment_sort[0] = 0;
    new_msg->rx_fragment->fragment_info[0].fragment_buffer = buffer;
    new_msg->rx_fragment->fragment_info[0].fragment_start_offset = ipv4_hdr_offset(ip_hdr);
    new_msg->rx_fragment->fragment_info[0].fragment_end_offset = (uint16_t)(ipv4_hdr_offset(ip_hdr) + ipv4_hdr_body_len(ip_hdr));
    new_msg->rx_fragment->expires_cd = EHIP_IP_FRAGMENT_TIMEOUT;
    return new_msg;

eh_mem_pool_alloc_ip_rx_fragment_fail:
    _ip_message_rx_free(new_msg);
ip_message_rx_new_err:
    ehip_buffer_free(buffer);
    return NULL;
}


int  ip_message_rx_data_size(struct ip_message *msg_hander){
    eh_param_assert(msg_hander);
    eh_param_assert(ip_message_flag_is_rx(msg_hander));
    if(ip_message_flag_is_fragment(msg_hander)){
        return msg_hander->rx_fragment->fragment_buffer_size;
    }else{
        return ehip_buffer_get_payload_size(msg_hander->buffer);
    }
}

int _ip_message_rx_read_advanced(struct ip_message *msg_hander, uint8_t **out_data, 
    ehip_buffer_size_t size, uint8_t *out_bak_buffer, enum _ip_message_read_advanced_type type, bool is_copy){

    // 单次读的最大数据量
    ehip_buffer_size_t              single_max_read_size = 0;
    eh_param_assert(msg_hander);
    eh_param_assert(ip_message_flag_is_rx(msg_hander));
    
    if(!ip_message_flag_is_fragment(msg_hander)){
        single_max_read_size = ehip_buffer_get_payload_size(msg_hander->buffer);
        size = single_max_read_size < size ? single_max_read_size : size;
        if(type != IP_MESSAGE_READ_ADVANCED_TYPE_READ_SKIP ){
            if(is_copy){
                memcpy(out_bak_buffer, ehip_buffer_get_payload_ptr(msg_hander->buffer), size);
                *out_data = out_bak_buffer;
            }else{
                *out_data = (uint8_t *)ehip_buffer_get_payload_ptr(msg_hander->buffer);
            }
        }
        if(type != IP_MESSAGE_READ_ADVANCED_TYPE_PEEK ){
            ehip_buffer_head_reduce(msg_hander->buffer, size);
        }
        return size;
    }
    /* 分片模式 */
    {
        ehip_buffer_size_t              fragment_size;
        int                             sort_i = 1, tmp_i;
        ehip_buffer_t                  *buffer;
        uint8_t                        *write_data_ptr;
        struct fragment_info           *first_fragment_buffer;

        first_fragment_buffer = &msg_hander->rx_fragment->fragment_info[0];
        if(ehip_buffer_get_payload_size(first_fragment_buffer->fragment_buffer) >= size){
            if(type != IP_MESSAGE_READ_ADVANCED_TYPE_READ_SKIP ){
                if(is_copy){
                    memcpy(out_bak_buffer, ehip_buffer_get_payload_ptr(first_fragment_buffer->fragment_buffer), size);
                    *out_data = out_bak_buffer;
                }else{
                    *out_data = (uint8_t *)ehip_buffer_get_payload_ptr(first_fragment_buffer->fragment_buffer);
               }
            }
            if(type != IP_MESSAGE_READ_ADVANCED_TYPE_PEEK ){
                ehip_buffer_head_reduce(first_fragment_buffer->fragment_buffer, size);
                msg_hander->rx_fragment->fragment_buffer_size -= size;
            }
            return size;
        }
        write_data_ptr = out_bak_buffer;

        ip_message_rx_fragment_for_each(buffer, tmp_i, sort_i, msg_hander){
            fragment_size = ehip_buffer_get_payload_size(buffer);
            if(fragment_size == 0)
                continue;
            single_max_read_size = fragment_size < size ? fragment_size : size;

            if(type != IP_MESSAGE_READ_ADVANCED_TYPE_READ_SKIP )
                memcpy(write_data_ptr, ehip_buffer_get_payload_ptr(buffer), single_max_read_size);
            if(type != IP_MESSAGE_READ_ADVANCED_TYPE_PEEK ){
                ehip_buffer_head_reduce(buffer, single_max_read_size);
                msg_hander->rx_fragment->fragment_buffer_size -= single_max_read_size;
            }

            write_data_ptr += single_max_read_size;
            size -= single_max_read_size;
            if(size == 0)
                break;
        }
        return write_data_ptr - out_bak_buffer;
    }
    

}

static int __init ip_message_pool_init(void)
{
    int ret;
    ip_message_pool = eh_mem_pool_create(EHIP_POOL_BASE_ALIGN, sizeof(struct ip_message), EHIP_IP_MAX_BUFFER_NUM);
    if((ret = eh_ptr_to_error(ip_message_pool)) < 0 ){
        return ret;
    }
    ip_rx_fragment_pool = eh_mem_pool_create(EHIP_POOL_BASE_ALIGN, sizeof(struct ip_rx_fragment), EHIP_IP_MAX_IP_FRAGMENT_BUFFER_NUM);
    if((ret = eh_ptr_to_error(ip_rx_fragment_pool)) < 0 ){
        goto ip_rx_fragment_pool_err;
    }
    ip_tx_fragment_pool = eh_mem_pool_create(EHIP_POOL_BASE_ALIGN, sizeof(struct ip_tx_fragment), EHIP_IP_MAX_IP_FRAGMENT_BUFFER_NUM);
    if((ret = eh_ptr_to_error(ip_tx_fragment_pool)) < 0 ){
        goto ip_tx_fragment_pool_err;
    }
    options_bytes_pool = eh_mem_pool_create(EHIP_POOL_BASE_ALIGN, IP_OPTIONS_MAX_LEN, EHIP_IP_MAX_IP_OPTIONS_BYTES_BUFFER_NUM);
    if((ret = eh_ptr_to_error(options_bytes_pool)) < 0 ){
        goto options_bytes_pool_err;
    }
    return 0;
options_bytes_pool_err:
    eh_mem_pool_destroy(ip_tx_fragment_pool);
ip_tx_fragment_pool_err:
    eh_mem_pool_destroy(ip_rx_fragment_pool);
ip_rx_fragment_pool_err:
    eh_mem_pool_destroy(ip_message_pool);
    return ret;
}

static void __exit ip_message_pool_exit(void)
{
    eh_mem_pool_destroy(options_bytes_pool);
    eh_mem_pool_destroy(ip_tx_fragment_pool);
    eh_mem_pool_destroy(ip_rx_fragment_pool);
    eh_mem_pool_destroy(ip_message_pool);
}

ehip_preinit_module_export(ip_message_pool_init, ip_message_pool_exit);
