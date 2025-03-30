/**
 * @file icmp.c
 * @brief 参考 rfc792
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-12-31
 *
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 *
 */


#include <ehip-ipv4/icmp.h>
#include <ehip-ipv4/ip_message.h>

void icmp_input(struct ip_message *ip_msg){
    int ret;
    struct icmp_hdr *icmp_hdr;
    struct icmp_hdr icmp_hdr_tmp;

    ret = ip_message_rx_read(ip_msg, (uint8_t**)&icmp_hdr, sizeof(struct icmp_hdr), (uint8_t*)&icmp_hdr_tmp);
    if(ret != sizeof(struct icmp_hdr)){
        goto drop;
    }
    switch(icmp_hdr->type){
        case ICMP_TYPE_ECHO_REPLY:
        case ICMP_TYPE_ECHO:{
            void ping_input(struct ip_message *ip_msg, const struct icmp_hdr *icmp_hdr);
            ping_input(ip_msg, icmp_hdr);
            return ;
        }
        default:
            break;
    }
drop:
    ip_message_free(ip_msg);
    return ;
}