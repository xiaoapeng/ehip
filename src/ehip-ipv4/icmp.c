/**
 * @file icmp.c
 * @brief 
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-12-31
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 *
 */


#include <ehip-ipv4/icmp.h>
#include <ehip-ipv4/ip_message.h>
int icmp_input(struct ip_message *ip_msg){
    (void)ip_msg;
    ip_message_free(ip_msg);
    return 0;
}