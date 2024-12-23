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
static eh_mem_pool_t ip_hdr_pool;


struct ip_message *ip_message_new(enum ip_message_type type){
    struct ip_message * new_msg =  eh_mem_pool_alloc(ip_message_pool);
    if(new_msg == NULL)
        return NULL;
    memset(new_msg, 0, sizeof(struct ip_message));
    new_msg->type = (uint8_t)type;
    if(type == IP_MESSAGE_TYPE_FRAGMENT){
        struct ip_fragment *fragment = eh_mem_pool_alloc(ip_hdr_pool);
        if(fragment == NULL)
            goto ip_hdr_pool_alloc_error;
        new_msg->fragment = fragment;
        new_msg->fragment_buffer = fragment->fragment;
    }
    return new_msg;
ip_hdr_pool_alloc_error:
    eh_mem_pool_free(ip_message_pool, new_msg);
    return NULL;
}

void ip_message_and_buffer_free(struct ip_message *msg){
    if(msg->type == IP_MESSAGE_TYPE_FRAGMENT){
        if(msg->fragment_buffer){
            for(int i = 0; i < msg->fragment_num; i++)
                ehip_buffer_free(msg->fragment_buffer[i]);
        }
        eh_mem_pool_free(ip_hdr_pool, msg->fragment);
    }else{
        if(msg->buffer)
            ehip_buffer_free(msg->buffer);
    }
    eh_mem_pool_free(ip_message_pool, msg);
}


#if EHIP_IP_MAX_BUFFER_NUM/2 <= 0
#error "EHIP_IP_MAX_BUFFER_NUM/2 must be greater than 0" 
#endif

static int __init ip_message_pool_init(void)
{
    int ret;
    ip_message_pool = eh_mem_pool_create(EHIP_POOL_BASE_ALIGN, sizeof(struct ip_message), EHIP_IP_MAX_BUFFER_NUM);
    if((ret = eh_ptr_to_error(ip_message_pool)) < 0 ){
        return ret;
    }
    ip_hdr_pool = eh_mem_pool_create(EHIP_POOL_BASE_ALIGN, sizeof(struct ip_fragment), EHIP_IP_MAX_IP_FRAGMENT_BUFFER_NUM);
    if((ret = eh_ptr_to_error(ip_hdr_pool)) < 0 ){
        eh_mem_pool_destroy(ip_message_pool);
        return ret;
    }
    return 0;
}

static void __exit ip_message_pool_exit(void)
{
    eh_mem_pool_destroy(ip_hdr_pool);
    eh_mem_pool_destroy(ip_message_pool);
}

ehip_preinit_module_export(ip_message_pool_init, ip_message_pool_exit);
