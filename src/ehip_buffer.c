/**
 * @file ehip_buffer.c
 * @brief 
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-10-13
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */

#include <stdint.h>
#include <string.h>

#include <eh.h>
#include <eh_debug.h>
#include <eh_mem_pool.h>
#include <eh_error.h>

#include <ehip_module.h>
#include <ehip_buffer.h>
#include <ehip_conf.h>

#define EHIP_BUFFER_REF_MAX_NUM UINT16_MAX

static eh_mem_pool_t pool_tab[EHIP_BUFFER_TYPE_MAX];
static eh_mem_pool_t pool_ehip_buffer_ref;
static eh_mem_pool_t pool_ehip_buffer;
struct ehip_pool_info {
    const char *name;
    ehip_buffer_size_t    size;
    ehip_buffer_size_t    num;
    ehip_buffer_size_t    align;
};
static const struct ehip_pool_info ehip_pool_info_tab[EHIP_BUFFER_TYPE_MAX] = {
    [EHIP_BUFFER_TYPE_GENERAL_FRAME] = {"general-network-buffer", EHIP_NETDEV_TYPE_GENERAL_POOL_BUFFER_SIZE, EHIP_NETDEV_TYPE_GENERAL_POOL_BUFFER_NUM, EHIP_NETDEV_TYPE_GENERAL_POOL_BUFFER_ALIGN}
};

static ehip_buffer_t* _ehip_buffer_new(enum ehip_buffer_type type, ehip_buffer_size_t head_reserved_size_or_0, ehip_buffer_raw_ptr buffer_raw_ptr){
    ehip_buffer_t *buf;
    struct ehip_buffer_ref *buf_ref;
    int ret;
    if((uint32_t)type >= EHIP_BUFFER_TYPE_MAX || ehip_pool_info_tab[type].size < head_reserved_size_or_0)
        return eh_error_to_ptr(EH_RET_INVALID_PARAM);
    
    buf = eh_mem_pool_alloc(pool_ehip_buffer);
    if(buf == NULL){
        eh_merrfl(EHIP_BUFFER, "type: pool_ehip_buffer alloc fail");
        return eh_error_to_ptr(EH_RET_MEM_POOL_EMPTY);
    }
    
    buf_ref = eh_mem_pool_alloc(pool_ehip_buffer_ref);
    if(buf_ref == NULL){
        eh_merrfl(EHIP_BUFFER, "type: pool_ehip_buffer_ref alloc fail");
        ret = EH_RET_MEM_POOL_EMPTY;
        goto eh_mem_pool_alloc_buffer_ref_fail;
    }
    
    buf_ref->buffer = buffer_raw_ptr;
    buf->buffer_ref = buf_ref;
    buf->payload_pos = head_reserved_size_or_0;
    buf->payload_tail = head_reserved_size_or_0;
    buf->flags = 0;
    buf_ref->buffer = buf_ref->buffer;
    buf_ref->ref_cnt = 1;
    buf_ref->type = type;
    buf_ref->buffer_size = ehip_pool_info_tab[type].size;
    return buf;
eh_mem_pool_alloc_buffer_ref_fail:
    eh_mem_pool_free(pool_ehip_buffer, buf);
    return eh_error_to_ptr(ret);;
}

ehip_buffer_raw_ptr ehip_buffer_new_raw_ptr(enum ehip_buffer_type type){
    if((uint32_t)type >= EHIP_BUFFER_TYPE_MAX)
        return NULL;
    return eh_mem_pool_alloc(pool_tab[type]);
}

void ehip_buffer_free_raw_ptr(enum ehip_buffer_type type, ehip_buffer_raw_ptr buf){
    eh_mem_pool_free(pool_tab[type], buf);
}

void ehip_buffer_free(ehip_buffer_t* buf){
    if(buf->buffer_ref->ref_cnt > 0){
        buf->buffer_ref->ref_cnt--;
    }else{
        eh_mwarnfl(EHIP_BUFFER, "ref_cnt == 0");
    }
    if(buf->buffer_ref->ref_cnt == 0){
        eh_mem_pool_free(pool_tab[buf->buffer_ref->type], buf->buffer_ref->buffer);
        eh_mem_pool_free(pool_ehip_buffer_ref, buf->buffer_ref);
    }
    eh_mem_pool_free(pool_ehip_buffer, buf);
}


ehip_buffer_t* ehip_buffer_new(enum ehip_buffer_type type, ehip_buffer_size_t head_reserved_size_or_0){
    void* buffer_ptr;
    ehip_buffer_t* new_buf;
    if((uint32_t)type >= EHIP_BUFFER_TYPE_MAX || ehip_pool_info_tab[type].size < head_reserved_size_or_0)
        return eh_error_to_ptr(EH_RET_INVALID_PARAM);
    
    buffer_ptr = eh_mem_pool_alloc(pool_tab[type]);
    if(buffer_ptr == NULL){
        eh_errfl("type: %d alloc fail", type);
        return eh_error_to_ptr(EH_RET_MEM_POOL_EMPTY);
    }

    new_buf = _ehip_buffer_new(type, head_reserved_size_or_0, buffer_ptr);
    if(eh_ptr_to_error(new_buf) < 0)
        eh_mem_pool_free(pool_tab[type], buffer_ptr);
    return new_buf;
}

extern ehip_buffer_t* ehip_buffer_new_from_buf(enum ehip_buffer_type type, ehip_buffer_raw_ptr buf){
    if(eh_mem_pool_ptr_to_idx(pool_tab[type], buf) < 0)
        return eh_error_to_ptr(EH_RET_INVALID_PARAM);
    return _ehip_buffer_new(type, 0, buf);
}

ehip_buffer_t* ehip_buffer_dup(ehip_buffer_t* src){
    ehip_buffer_t* new_buffer = ehip_buffer_new(src->buffer_ref->type, 0);
    if(eh_ptr_to_error(new_buffer) < 0)
        return new_buffer;
    new_buffer->payload_pos = src->payload_pos;
    new_buffer->payload_tail = src->payload_tail;
    new_buffer->protocol = src->protocol;
    new_buffer->netdev = src->netdev;
    new_buffer->flags = src->flags;
    memcpy(ehip_buffer_get_payload_ptr(new_buffer), ehip_buffer_get_payload_ptr(src), ehip_buffer_get_payload_size(src));
    return new_buffer;
}

ehip_buffer_t* ehip_buffer_ref_dup(ehip_buffer_t* buf){
    ehip_buffer_t* new_buffer;
    
    if(buf->buffer_ref->ref_cnt == EHIP_BUFFER_REF_MAX_NUM)
        return eh_error_to_ptr(EH_RET_INVALID_STATE);
    new_buffer = eh_mem_pool_alloc(pool_ehip_buffer);
    if(new_buffer == NULL)
        return eh_error_to_ptr(EH_RET_MEM_POOL_EMPTY);
    buf->buffer_ref->ref_cnt++;
    *new_buffer = *buf;
    return new_buffer;
}

uint8_t* ehip_buffer_payload_append(ehip_buffer_t* buf, ehip_buffer_size_t size){
    uint8_t *new_payload_ptr = ehip_buffer_get_payload_end_ptr(buf);
    if((int)((buf->payload_tail) + size) > (int)ehip_buffer_get_buffer_size(buf))
        return NULL;
    buf->payload_tail += size;
    return new_payload_ptr;
}


uint8_t* ehip_buffer_payload_reduce(ehip_buffer_t* buf, ehip_buffer_size_t size){
    uint8_t *remove_payload_ptr;
    if((int)ehip_buffer_get_payload_size(buf) < (int)size)
        return NULL;
    remove_payload_ptr = ehip_buffer_get_payload_end_ptr(buf) - size;
    buf->payload_tail -= size;
    return remove_payload_ptr;
}


uint8_t* ehip_buffer_head_append(ehip_buffer_t* buf, ehip_buffer_size_t size){
    if(buf->payload_pos < size)
        return NULL;
    buf->payload_pos -= size;
    return ehip_buffer_get_payload_ptr(buf);
}

uint8_t* ehip_buffer_head_reduce(ehip_buffer_t* buf, ehip_buffer_size_t size){
    uint8_t *old_payload_ptr;
    if((int)ehip_buffer_get_payload_size(buf) < (int)size)
        return NULL;
    old_payload_ptr = ehip_buffer_get_payload_ptr(buf);
    buf->payload_pos += size;
    return old_payload_ptr;
}

static __init int ehip_buffer_init(void){
    const struct ehip_pool_info *info;
    int i=0;
    int ret;
    size_t sum_num = 0;

    for(i = 0; i < EHIP_BUFFER_TYPE_MAX; i++){
        info = &ehip_pool_info_tab[i];
        sum_num += info->num;
        pool_tab[i] = eh_mem_pool_create(info->align, info->size, info->num);
        ret = eh_ptr_to_error(pool_tab[i]);
        if(ret < 0)
            goto eh_mem_pool_create_fail;
        eh_mdebugfl(EHIP_BUFFER, "mem pool [%s]:%#0p", info->name, pool_tab[i]);
    }

    pool_ehip_buffer_ref = eh_mem_pool_create(sizeof(void*), sizeof(struct ehip_buffer_ref), sum_num);
    ret = eh_ptr_to_error(pool_ehip_buffer_ref);
    if(ret < 0)
        goto create_ehip_buffer_ref_pool_fail;
    eh_mdebugfl(EHIP_BUFFER, "mem pool [ehip_buffer_ref]:%#0p", pool_ehip_buffer_ref);
    
    pool_ehip_buffer = eh_mem_pool_create(sizeof(void*), sizeof(struct ehip_buffer), EHIP_NETDEV_POLL_BUFFER_MAX_NUM);
    ret = eh_ptr_to_error(pool_ehip_buffer);
    if(ret < 0)
        goto create_ehip_buffer_fail;
    eh_mdebugfl(EHIP_BUFFER, "mem pool [ehip_buffer]:%#0p", pool_ehip_buffer);

    return 0;

create_ehip_buffer_fail:
    eh_mem_pool_destroy(pool_ehip_buffer_ref);
create_ehip_buffer_ref_pool_fail:
eh_mem_pool_create_fail:
    while(i--)
        eh_mem_pool_destroy(pool_tab[i]);
    return ret;
}

static __exit void ehip_buffer_exit(void){
    eh_mem_pool_destroy(pool_ehip_buffer);
    eh_mem_pool_destroy(pool_ehip_buffer_ref);
    for(int i = 0; i < EHIP_BUFFER_TYPE_MAX; i++){
        eh_mem_pool_destroy(pool_tab[i]);
    }
}

ehip_preinit_module_export(ehip_buffer_init, ehip_buffer_exit);
