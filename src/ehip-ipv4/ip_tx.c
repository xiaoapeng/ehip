/**
 * @file ip_tx.c
 * @brief 发送ip包
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-03-18
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */

#include <eh_debug.h>
#include <ehip_core.h>
#include <ehip-ipv4/ip.h>
#include <ehip-ipv4/ip_tx.h>

void ip_tx(struct ip_message *ip_msg){
    ehip_buffer_t *pos_buffer;
    ehip_buffer_t *tx_pos_buffer;
    int tmp_i;
    if(!ip_message_flag_is_tx(ip_msg))
        goto quit;
    
    if(ip_message_flag_is_fragment(ip_msg)){
        ip_message_tx_fragment_for_each(pos_buffer, tmp_i, ip_msg){
            tx_pos_buffer = ehip_buffer_ref_dup(pos_buffer);
            ehip_queue_tx(tx_pos_buffer);
        }
    }else{
        tx_pos_buffer = ehip_buffer_ref_dup(ip_msg->buffer);
        ehip_queue_tx(tx_pos_buffer);
    }
quit:
    ip_message_free(ip_msg);
    return ;
}
