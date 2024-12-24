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
    if(fragment->fragment_num == 0 || new_msg->fragment_num > 0)
        return EH_RET_INVALID_PARAM;
    /* 插入 TODO */
    return EH_RET_INVALID_PARAM;
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
