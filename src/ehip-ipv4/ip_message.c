/**
 * @file ip_message.c
 * @brief 
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-12-21
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */
#include <string.h>
#include <eh_error.h>
#include <eh_mem_pool.h>
#include <eh_types.h>
#include <eh_debug.h>
#include <ehip_buffer.h>
#include <ehip_module.h>
#include <ehip-ipv4/ip.h>
#include <ehip-ipv4/ip_message.h>


eh_static_assert(EHIP_IP_MAX_FRAGMENT_NUM < 0xFE, "IP fragment number must less than 0xFE");

/* 当fragment_num为 0xFF时，说明这个分片的ip报文已经破碎了，该状态存在的唯一意义就是防止剩下的分片进入 */
#define IP_MESSAGE_FRAGMENT_BROKEN_VALUE  0xFF

#define ip_message_is_broken(msg)   ((msg)->fragment_num == IP_MESSAGE_FRAGMENT_BROKEN_VALUE)

static eh_mem_pool_t ip_message_pool;
static eh_mem_pool_t ip_fragment_pool;


static void ip_message_fragment_boroken(struct ip_message *msg){
    int i, sort_i;
    ehip_buffer_t *pos_buffer;
    ip_message_fragment_for_each(pos_buffer, i, sort_i, msg){
        ehip_buffer_free(pos_buffer);
    }
    msg->fragment_num = IP_MESSAGE_FRAGMENT_BROKEN_VALUE;
}
struct ip_message *ip_message_new(void){
    struct ip_message * new_msg =  eh_mem_pool_alloc(ip_message_pool);
    if(new_msg == NULL)
        return NULL;
    memset(new_msg, 0, sizeof(struct ip_message));
    return new_msg;
}

void ip_message_free_and_buffer_clean(struct ip_message *msg){
    if(eh_unlikely(ip_message_is_broken(msg))){
        eh_mem_pool_free(ip_fragment_pool, msg->fragment);
    }else if(msg->fragment_num > 0){
        int i, sort_i;
        ehip_buffer_t *pos_buffer;
        ip_message_fragment_for_each(pos_buffer, i, sort_i, msg){
            ehip_buffer_free(pos_buffer);
        }
        eh_mem_pool_free(ip_fragment_pool, msg->fragment);
    }else{
        if(msg->buffer)
            ehip_buffer_free(msg->buffer);
    }
    eh_mem_pool_free(ip_message_pool, msg);
}


int ip_message_convert_to_fragment(struct ip_message *msg){
    if(msg->fragment_num > 0 || ip_message_is_broken(msg))
        return 0;
    struct ip_fragment *fragment;
    if(msg->buffer == NULL || msg->ip_hdr == NULL) 
        return EH_RET_INVALID_PARAM;
    fragment = eh_mem_pool_alloc(ip_fragment_pool);
    if(fragment == NULL)
        return EH_RET_MEM_POOL_EMPTY;
    fragment->ip_hdr.ihl = msg->ip_hdr->ihl;
    fragment->ip_hdr.version = msg->ip_hdr->version;
    fragment->ip_hdr.tos = msg->ip_hdr->tos;
    /* 如果mf置位那么说明是中间报文 */
    if(ipv4_hdr_is_mf(msg->ip_hdr)){
        /* 如果没有收到最后一个分片数据，那就设置为0 */
        fragment->ip_hdr.tot_len = 0; /* 当此成员为 */
    }else{
        /* 
         * 如果最后一个分片数据，那就通过该分片数据得到最终的数据包长度，
         * 此时，该成员以主机字节序来存储，而且不包含头部大小，当
         * 当能收到完整的IP分片后，将转换为网络字节序，并且会算上头部的大小
         */
        fragment->ip_hdr.tot_len = (uint16_be_t)(ipv4_hdr_offset(msg->ip_hdr) + ipv4_hdr_body_len(msg->ip_hdr));
    }
    fragment->ip_hdr.id = msg->ip_hdr->id;
    fragment->ip_hdr.frag_off = 0;
    fragment->ip_hdr.ttl = msg->ip_hdr->ttl;
    fragment->ip_hdr.protocol = msg->ip_hdr->protocol;
    fragment->ip_hdr.check = 0;
    fragment->ip_hdr.src_addr = msg->ip_hdr->src_addr;
    fragment->ip_hdr.dst_addr = msg->ip_hdr->dst_addr;

    fragment->fragment_info[0].fragment_buffer = msg->buffer;
    fragment->fragment_info[0].fragment_start_offset = ipv4_hdr_offset(msg->ip_hdr);
    fragment->fragment_info[0].fragment_end_offset = (uint16_t)(ipv4_hdr_offset(msg->ip_hdr) + ipv4_hdr_body_len(msg->ip_hdr));
    fragment->fragment_sort[0] = 0;
    msg->fragment = fragment;
    msg->fragment_num = 1;
    msg->expires_cd = EHIP_IP_FRAGMENT_TIMEOUT;
    return 0;
}

int ip_message_add_fragment(struct ip_message *fragment, struct ip_message *new_msg){
    ehip_buffer_t *buffer_ptr;
    uint16_t fragment_start_offset;
    uint16_t fragment_end_offset;
    uint16_t fragment_check_offset;
    struct ip_hdr *new_msg_ip_hdr;
    struct fragment_info *prev_fragment_msg;
    struct fragment_info *fragment_msg;
    int sort_i, ret, install_index;
    

    if(fragment->fragment_num == 0 || new_msg->fragment_num > 0)
        return EH_RET_INVALID_PARAM;
    
    if(ip_message_is_broken(fragment)){
        fragment->expires_cd = EHIP_IP_FRAGMENT_TIMEOUT/2;
        return 0;
    }
    
    buffer_ptr = ehip_buffer_ref_dup(new_msg->buffer);
    new_msg_ip_hdr = new_msg->ip_hdr;

    fragment_start_offset = ipv4_hdr_offset(new_msg->ip_hdr);
    fragment_end_offset = (uint16_t)(ipv4_hdr_offset(new_msg->ip_hdr) + ipv4_hdr_body_len(new_msg->ip_hdr));

    if(ipv4_hdr_is_mf(new_msg_ip_hdr)){
        /* 
         * 中间的分片必须以8字对齐 
         * 或者分片数量达到最大值时还没有得到最后一块分片
         */
        if( ipv4_hdr_body_len(new_msg_ip_hdr) & 0x7 ){
            /* ip中间的分片没有向8字节对齐 */
            eh_debugfl("Ip fragment not align 8.");
            ret = EH_RET_INVALID_STATE;
            goto drop;
        }

        if(fragment->fragment->ip_hdr.tot_len == 0 && fragment->fragment_num + 1 >= (uint8_t)EHIP_IP_MAX_FRAGMENT_NUM){
            /* 
             * 如果分片数量达到最大值时还没有得到最后一块分片
             * 那么就不再接收新的分片
             */
            eh_debugfl("Ip fragment max.");
            ip_message_fragment_boroken(fragment);
            fragment->expires_cd = EHIP_IP_FRAGMENT_TIMEOUT/2;
            ret = EH_RET_OK;
            goto drop;
        }
    }else{
        /* 最后一个分片报文 */
        if( fragment->ip_hdr->tot_len ){
            /* 重复接收到最后一片报文 */
            eh_debugfl("Ip fragment repeat.");
            ret = EH_RET_OK;
            goto drop;
        }
        fragment->ip_hdr->tot_len = 
            (uint16_be_t)(ipv4_hdr_offset(new_msg_ip_hdr) + ipv4_hdr_body_len(new_msg_ip_hdr));
    }

    fragment->fragment->fragment_info[fragment->fragment_num].fragment_buffer = buffer_ptr;
    fragment->fragment->fragment_info[fragment->fragment_num].fragment_start_offset = fragment_start_offset;
    fragment->fragment->fragment_info[fragment->fragment_num].fragment_end_offset = fragment_end_offset;

    prev_fragment_msg = NULL;
    for( install_index = 0; 
            install_index < fragment->fragment_num; 
            install_index++, prev_fragment_msg = fragment_msg   ){
        sort_i = fragment->fragment->fragment_sort[install_index];
        fragment_msg = fragment->fragment->fragment_info + sort_i;

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
        for(    int j = fragment->fragment_num; 
                j > install_index; 
                j-- ){
            fragment->fragment->fragment_sort[j] = fragment->fragment->fragment_sort[j - 1];
        }
        break;
    }
    fragment->fragment->fragment_sort[install_index] = fragment->fragment_num;
    fragment->expires_cd = EHIP_IP_FRAGMENT_TIMEOUT;
    fragment->fragment_num++;
    /* 插入成功后，检查是否已经拿到了尾部，若拿到了尾部，则进行完整性检测*/
    if(fragment->ip_hdr->tot_len == 0)
        return 0;
    fragment_check_offset = 0;
    for(int i=0; i < fragment->fragment_num; i++){
        sort_i = fragment->fragment->fragment_sort[i];
        fragment_msg = fragment->fragment->fragment_info + sort_i;
        if(fragment_check_offset != fragment_msg->fragment_start_offset)
            return 0;
        fragment_check_offset = fragment_msg->fragment_end_offset;
    }
    fragment->ip_hdr->tot_len = eh_hton16(fragment_check_offset);

    return FRAGMENT_REASSE_FINISH;
drop:
    ehip_buffer_free(buffer_ptr);
    return ret;
}

static int __init ip_message_pool_init(void)
{
    int ret;
    ip_message_pool = eh_mem_pool_create(EHIP_POOL_BASE_ALIGN, sizeof(struct ip_message), EHIP_IP_MAX_BUFFER_NUM);
    if((ret = eh_ptr_to_error(ip_message_pool)) < 0 ){
        return ret;
    }
    ip_fragment_pool = eh_mem_pool_create(EHIP_POOL_BASE_ALIGN, sizeof(struct ip_fragment), EHIP_IP_MAX_IP_FRAGMENT_BUFFER_NUM);
    if((ret = eh_ptr_to_error(ip_fragment_pool)) < 0 ){
        eh_mem_pool_destroy(ip_message_pool);
        return ret;
    }
    return 0;
}

static void __exit ip_message_pool_exit(void)
{
    eh_mem_pool_destroy(ip_fragment_pool);
    eh_mem_pool_destroy(ip_message_pool);
}

ehip_preinit_module_export(ip_message_pool_init, ip_message_pool_exit);
