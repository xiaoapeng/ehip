/**
 * @file ip_message.h
 * @brief 
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-12-21
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */

#ifndef _IP_MESSAGE_H_
#define _IP_MESSAGE_H_

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */


#include "eh_types.h"
#include <eh_mem_pool.h>

#include <ehip-ipv4/ip.h>
#include <stdint.h>

typedef struct ehip_buffer ehip_buffer_t;


struct ip_fragment{
    struct ip_hdr    ip_hdr;
    uint8_t         fragment_sort[EHIP_IP_MAX_FRAGMENT_NUM];
    struct{
        ehip_buffer_t      *fragment_buffer;
        uint16_t            fragment_start_offset;
        uint16_t            fragment_end_offset;
    }fragment_info[EHIP_IP_MAX_FRAGMENT_NUM];
};

eh_static_assert(eh_offsetof(struct ip_fragment, ip_hdr) == 0, "ip_hdr must be the first member of ip_fragment");

struct ip_message{
    union{
        struct ip_hdr               *ip_hdr;
        struct ip_fragment          *fragment;
    };
    ehip_buffer_t               *buffer;
    uint8_t                     fragment_num;
    uint8_t                     expires_cd;
};

/**
 * @brief    创建一个的IP报文结构 
 * @return struct ip_message* 
 */
extern struct ip_message* ip_message_new(void);

/**
 * @brief     释放一个 ip_message_t 结构体,若内部拥有ehip_buffer_t 则一同解除引用
 * @param  msg                 要释放的 ip_message_t 结构体
 */
extern void ip_message_and_buffer_free(struct ip_message *msg);

/**
 * @brief     将一个普通的 ip_message_t 结构体转换为一个分片片段的 ip_message_t 结构体
 * @param  msg                  要转换的 ip_message_t 结构体
 * @return struct ip_fragment*  成功返回0，失败返回负数
 */
extern int ip_message_convert_to_fragment(struct ip_message *msg);

/**
 * @brief                将一个ip_message_t 结构体添加到分片的 ip_message_t 结构体中
 * @param  fragment      要添加的分片片段的 ip_message_t 结构体
 * @param  new_msg       要添加到的分片片段的 ip_message_t 结构体,
*                          无论成功还是失败，本函数不对new_msg的空间做任何改变，需要自己调用ip_message_and_buffer_free释放
 * @return int           成功返回0，失败返回负数
 */
extern int ip_message_add_fragment(struct ip_message *fragment, struct ip_message *new_msg);


/**
 * @brief      遍历一个分片片段的 ip_message_t 结构体
 * @param  pos_buffer       分片片段的 ehip_buffer_t 结构体指针
 * @param  int_tmp_i        分片片段的索引,临时使用
 * @param  int_tmp_sort_i   分片片段的排序索引，临时使用
 * @param  ip_fragment_msg  要遍历的 ip_message_t 结构体
 */
#define ip_message_fragment_for_each(pos_buffer, int_tmp_i, int_tmp_sort_i,  ip_fragment_msg) \
    for( int_tmp_i = 0, int_tmp_sort_i = ip_fragment_msg->fragment->fragment_sort[int_tmp_i]; \
        int_tmp_i < ip_fragment_msg->fragment_num && int_tmp_sort_i < (int)EHIP_IP_MAX_FRAGMENT_NUM && \
        ((pos_buffer = ip_fragment_msg->fragment->fragment_info[int_tmp_sort_i].fragment_buffer) || 1U); \
        int_tmp_sort_i = ip_fragment_msg->fragment->fragment_sort[++int_tmp_i])


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _IP_MESSAGE_H_