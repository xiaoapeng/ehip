/**
 * @file ip_raw_error.c
 * @brief 
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-05-09
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */

#include <ehip-ipv4/ip_raw_error.h>



void ip_raw_error(ipv4_addr_t err_sender, struct ip_hdr *ip_hdr, const uint8_t *payload, int payload_len, int error){
    switch (ip_hdr->protocol) {
        case IP_PROTO_ICMP:{
            extern void ping_error_input(ipv4_addr_t err_sender, struct ip_hdr *ip_hdr, const uint8_t *payload, int payload_len, int error);
            ping_error_input(err_sender, ip_hdr, payload, payload_len, error);
            break;
        }
        case IP_PROTO_UDP:
        case IP_PROTO_UDPLITE:{
            extern void udp_error_input(ipv4_addr_t err_sender, struct ip_hdr *ip_hdr, const uint8_t *payload, int payload_len, int error);
            udp_error_input(err_sender, ip_hdr, payload, payload_len, error);
            break;
        }
        default:
            break;
    }
}