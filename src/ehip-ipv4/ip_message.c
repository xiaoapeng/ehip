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
#include <ehip_buffer.h>
#include <ehip_module.h>
#include <ehip-ipv4/ip.h>
#include <ehip-ipv4/ip_message.h>




static eh_mem_pool_t ip_message_pool;
static eh_mem_pool_t ip_fragment_pool;


struct ip_message *ip_message_new(void){
    struct ip_message * new_msg =  eh_mem_pool_alloc(ip_message_pool);
    if(new_msg == NULL)
        return NULL;
    memset(new_msg, 0, sizeof(struct ip_message));
    return new_msg;
}

void ip_message_and_buffer_free(struct ip_message *msg){

    if(msg->fragment_num > 0){
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
    if(msg->fragment_num > 0)
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
    if(!ipv4_hdr_mf(&fragment->ip_hdr)){
        /* 
         * 如果最后一个分片数据，那就通过该分片数据得到最终的数据包长度，
         * 此时，该成员以主机字节序来存储，而且不包含头部大小，当
         * 当能收到完整的IP分片后，将转换为网络字节序，并且会算上头部的大小
         */
        fragment->ip_hdr.tot_len = (uint16_be_t)(ipv4_hdr_offset(msg->ip_hdr) + ipv4_hdr_body_len(msg->ip_hdr));
    }else{
        /* 如果没有收到最后一个分片数据，那就设置为0 */
        fragment->ip_hdr.tot_len = 0; /* 当此成员为 */
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
    int sort_i, ret;

    if(fragment->fragment_num == 0 || new_msg->fragment_num > 0)
        return EH_RET_INVALID_PARAM;

    buffer_ptr = ehip_buffer_ref_dup(new_msg->buffer);
    new_msg_ip_hdr = new_msg->ip_hdr;

    fragment_start_offset = ipv4_hdr_offset(new_msg->ip_hdr);
    fragment_end_offset = (uint16_t)(ipv4_hdr_offset(new_msg->ip_hdr) + ipv4_hdr_body_len(new_msg->ip_hdr));

    if(ipv4_hdr_mf(new_msg_ip_hdr)){
        /* 
         * 中间的发片必须以8字对齐 
         * 或者分片数量达到最大值时还没有得到最后一块分片
         */
        if( ipv4_hdr_total_len(new_msg_ip_hdr) & 0x7 || 
            (fragment->fragment->ip_hdr.tot_len == 0 && fragment->fragment_num + 1 >= EHIP_IP_MAX_FRAGMENT_NUM) ){
                ret = EH_RET_INVALID_STATE;
                goto quit;
            }
    }else{
        /* 最后一个分片报文 */
        if( fragment->ip_hdr->tot_len ){
            /* 重复接收到最后一片报文 */
            ret = EH_RET_INVALID_STATE;
            goto quit;
        }
        fragment->ip_hdr->tot_len = 
            (uint16_be_t)(ipv4_hdr_offset(new_msg_ip_hdr) + ipv4_hdr_body_len(new_msg_ip_hdr));
    }

    fragment->fragment->fragment_info[fragment->fragment_num].fragment_buffer = buffer_ptr;
    fragment->fragment->fragment_info[fragment->fragment_num].fragment_start_offset = fragment_start_offset;
    fragment->fragment->fragment_info[fragment->fragment_num].fragment_end_offset = fragment_end_offset;

    prev_fragment_msg = NULL;
    for(    int i = 0; 
            i < fragment->fragment_num; 
            i++, prev_fragment_msg = fragment_msg   ){
        sort_i = fragment->fragment->fragment_sort[i];
        fragment_msg = fragment->fragment->fragment_info + sort_i;

        if( fragment_end_offset > fragment_msg->fragment_start_offset )
            continue;

        if( prev_fragment_msg == NULL || 
            fragment_start_offset < prev_fragment_msg->fragment_end_offset 
        ){
            /* 两片报文出现重叠 */
            ret = EH_RET_INVALID_STATE;
            goto quit;
        }
        /* 
         * 找到了合适的位置，准备插入，
         * 先整体后移，再插入 
         */
        for(    int j = fragment->fragment_num; 
                j > i; 
                j-- ){
            fragment->fragment->fragment_sort[j] = fragment->fragment->fragment_sort[j - 1];
        }
        fragment->fragment->fragment_sort[i] = fragment->fragment_num;
        break;
    }
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

    return 1;
quit:
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