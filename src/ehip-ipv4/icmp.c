/**
 * @file icmp.c
 * @brief 参考 rfc792
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-12-31
 *
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 *
 */

#include <eh_debug.h>
#include <ehip_chksum.h>
#include <ehip-ipv4/icmp.h>
#include <ehip-ipv4/ip_message.h>

void icmp_input(struct ip_message *ip_msg){
    int ret;
    struct icmp_hdr *icmp_hdr;
    struct icmp_hdr icmp_hdr_tmp;
    uint16_t        checksum = 0;

    ret = ip_message_rx_read(ip_msg, (uint8_t**)&icmp_hdr, sizeof(struct icmp_hdr), (uint8_t*)&icmp_hdr_tmp);
    if(ret != sizeof(struct icmp_hdr)){
        goto drop;
    }

    checksum = ehip_inet_chksum_accumulated(checksum, (uint8_t*)icmp_hdr, sizeof(struct icmp_hdr));
    if(ip_message_flag_is_fragment(ip_msg)){
        ehip_buffer_t *pos_buffer;
        int tmp_i, tmp_sort_i;
        uint16_t single_chksum_len;
        /* 分片数据校验 */
        ip_message_rx_fragment_for_each(pos_buffer, tmp_i, tmp_sort_i, ip_msg){
            single_chksum_len = ehip_buffer_get_payload_size(pos_buffer);
            checksum = ehip_inet_chksum_accumulated(checksum, 
                ehip_buffer_get_payload_ptr(pos_buffer), single_chksum_len);
        }

    }else{
        checksum = ehip_inet_chksum_accumulated(checksum, 
            ehip_buffer_get_payload_ptr(ip_msg->buffer), ehip_buffer_get_payload_size(ip_msg->buffer));
    }

    if(checksum != 0){
        eh_mwarnfl(ICMP_INPUT, "icmp checksum error %#hx", icmp_hdr->checksum);
        goto drop;
    }

    switch(icmp_hdr->type){
        case ICMP_TYPE_ECHO_REPLY:
        case ICMP_TYPE_ECHO:{
            void ping_input(struct ip_message *ip_msg, const struct icmp_hdr *icmp_hdr);
            ping_input(ip_msg, icmp_hdr);
            return ;
        }

        case ICMP_TYPE_DEST_UNREACH:
        case ICMP_TYPE_REDIRECT:
        case ICMP_TYPE_TIME_EXCEEDED:
        case ICMP_TYPE_PARAMETERPROB:{
            void icmp_error_input(struct ip_message *ip_msg, const struct icmp_hdr *icmp_hdr);
            icmp_error_input(ip_msg, icmp_hdr);
            return ;
        }
        case ICMP_TYPE_SOURCE_QUENCH:
        case ICMP_TYPE_TIMESTAMP:
        case ICMP_TYPE_TIMESTAMPREPLY:
        case ICMP_TYPE_INFO_REQUEST:
        case ICMP_TYPE_INFO_REPLY:
        case ICMP_TYPE_ADDRESS:
        case ICMP_TYPE_ADDRESSREPLY:
        default:
            break;
    }
drop:
    ip_message_free(ip_msg);
    return ;
}