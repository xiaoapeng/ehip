/**
 * @file icmp_error.c
 * @brief 差错报文处理
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-02-18
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */

#include <eh_types.h>
#include <eh_debug.h>
#include <ehip_error.h>
#include <ehip-ipv4/ip.h>
#include <ehip-ipv4/ip_message.h>
#include <ehip-ipv4/icmp.h>
#include <ehip-ipv4/ip_raw_error.h>
#include <stddef.h>

#define ICMP_ERROR_PAYLOAD_MAX_LEN 8



void icmp_error_input(struct ip_message *ip_msg, const struct icmp_hdr *icmp_hdr){
    struct ip_hdr *err_ip_hdr;
    struct ip_hdr err_ip_hdr_tmp;
    uint8_t icmp_error_payload[ICMP_ERROR_PAYLOAD_MAX_LEN];
    int icmp_error_payload_len;
    int error;
    
    eh_mdebugfl(ICMP_ERROR_INPUT, "############### RAW icmp error ###############");
    eh_mdebugfl(ICMP_ERROR_INPUT, "type:%d", icmp_hdr->type);
    eh_mdebugfl(ICMP_ERROR_INPUT, "code:%d", icmp_hdr->code);
    eh_mdebugfl(ICMP_ERROR_INPUT, "checksum:%d", icmp_hdr->checksum);
    eh_mdebugfl( ICMP_ERROR_INPUT, "error sender: %d.%d.%d.%d", 
        ipv4_addr_to_dec0(ip_msg->ip_hdr.src_addr), ipv4_addr_to_dec1(ip_msg->ip_hdr.src_addr),
        ipv4_addr_to_dec2(ip_msg->ip_hdr.src_addr), ipv4_addr_to_dec3(ip_msg->ip_hdr.src_addr));
    icmp_error_payload_len = ip_message_rx_data_size(ip_msg) - (int)sizeof(struct icmp_hdr);
    if( icmp_error_payload_len < 0 ){
        eh_mwarnfl(ICMP_ERROR_INPUT, "ip_message_rx_data_size(ip_msg) < sizeof(struct ip_hdr)");
        goto drop;
    }
    icmp_error_payload_len = icmp_error_payload_len > ICMP_ERROR_PAYLOAD_MAX_LEN ? ICMP_ERROR_PAYLOAD_MAX_LEN : icmp_error_payload_len;
    ip_message_rx_read(ip_msg, (uint8_t**)&err_ip_hdr, sizeof(struct ip_hdr), (uint8_t*)&err_ip_hdr_tmp);
    ip_message_rx_real_read(ip_msg, icmp_error_payload, (ehip_buffer_size_t)icmp_error_payload_len);
    eh_mdebugfl( ICMP_ERROR_INPUT, "######## ERROR IP HEADER ########");
    eh_mdebugfl( ICMP_ERROR_INPUT, "src: %d.%d.%d.%d", 
        ipv4_addr_to_dec0(err_ip_hdr->src_addr), ipv4_addr_to_dec1(err_ip_hdr->src_addr),
        ipv4_addr_to_dec2(err_ip_hdr->src_addr), ipv4_addr_to_dec3(err_ip_hdr->src_addr));
    eh_mdebugfl( ICMP_ERROR_INPUT, "dst: %d.%d.%d.%d", 
        ipv4_addr_to_dec0(err_ip_hdr->dst_addr), ipv4_addr_to_dec1(err_ip_hdr->dst_addr),
        ipv4_addr_to_dec2(err_ip_hdr->dst_addr), ipv4_addr_to_dec3(err_ip_hdr->dst_addr));
    eh_mdebugfl( ICMP_ERROR_INPUT, "tos:%02x", err_ip_hdr->tos);
    eh_mdebugfl( ICMP_ERROR_INPUT, "iphdr_len:%d", eh_ntoh16(err_ip_hdr->tot_len));
    eh_mdebugfl( ICMP_ERROR_INPUT, "id:%d", eh_ntoh16(err_ip_hdr->id));
    eh_mdebugfl( ICMP_ERROR_INPUT, "frag_off:%04x", eh_ntoh16(err_ip_hdr->frag_off));
    eh_mdebugfl( ICMP_ERROR_INPUT, "ttl:%d", err_ip_hdr->ttl);
    eh_mdebugfl( ICMP_ERROR_INPUT, "protocol:%02x", err_ip_hdr->protocol);
    eh_mdebugfl( ICMP_ERROR_INPUT, "payload:|%.*hhq|", icmp_error_payload_len, icmp_error_payload);

    switch (icmp_hdr->type){
        case ICMP_TYPE_DEST_UNREACH:{
            switch (icmp_hdr->code) {
                case ICMP_CODE_NET_UNREACH:
                    error = EHIP_RET_UNREACHABLE;
                    break;
                case ICMP_CODE_HOST_UNREACH:
                    error = EHIP_RET_HOST_UNREACHABLE;
                    break;
                case ICMP_CODE_PROT_UNREACH:
                    error = EHIP_RET_PROTOCOL_UNREACHABLE;
                    break;
                case ICMP_CODE_PORT_UNREACH:
                    error = EHIP_RET_PORT_UNREACHABLE;
                    break;
                case ICMP_CODE_FRAG_NEEDED:
                    error = EHIP_RET_FRAG_NEEDED;
                    break;
                case ICMP_CODE_SR_FAILED:
                    error = EHIP_RET_SRC_ROUTE_FAILED;
                    break;
                case ICMP_CODE_NET_UNKNOWN:
                    error = EHIP_RET_NET_UNKNOWN;
                    break;
                case ICMP_CODE_HOST_UNKNOWN:
                    error = EHIP_RET_HOST_UNKNOWN;
                    break;
                case ICMP_CODE_HOST_ISOLATED:
                    error = EHIP_RET_SRC_HOST_ISOLATED;
                    break;
                case ICMP_CODE_NET_ANO:
                    error = EHIP_RET_NET_PROHIBITED;
                    break;
                case ICMP_CODE_HOST_ANO:
                    error = EHIP_RET_HOST_PROHIBITED;
                    break;
                case ICMP_CODE_NET_UNR_TOS:
                case ICMP_CODE_HOST_UNR_TOS:
                case ICMP_CODE_PKT_FILTERED:
                case ICMP_CODE_PREC_VIOLATION:
                case ICMP_CODE_PREC_CUTOFF:
                    error = EHIP_RET_PROTOCOL_UNREACHABLE;
                    break;
                default:
                    goto drop;
            }
            break;
        }
        case ICMP_TYPE_REDIRECT:
            error = EHIP_RET_REDIRECTED;
            break;
        case ICMP_TYPE_TIME_EXCEEDED:
            error = EHIP_RET_TTL_EXPIRED;
            break;
        case ICMP_TYPE_PARAMETERPROB:
            error = EHIP_RET_PARAMETERPROB;
            break;
        default:
            goto drop;
    }
    
    /* 传递错误到上层 */
    ip_raw_error(ip_msg->ip_hdr.src_addr, err_ip_hdr, icmp_error_payload, icmp_error_payload_len, error);

drop:
    ip_message_free(ip_msg);
}