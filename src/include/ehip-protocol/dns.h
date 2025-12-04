/**
 * @file dns.h
 * @brief DNS protocol header file
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-11-23
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */
#ifndef _DNS_H_
#define _DNS_H_

#include <ehip-ipv4/ip.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

#define EHIP_DNS_TYPE_A          1U
//#define EHIP_DNS_TYPE_NS         2U
#define EHIP_DNS_TYPE_CNAME      5U
//#define EHIP_DNS_TYPE_SOA        6U
//#define EHIP_DNS_TYPE_MX        15U
//#define EHIP_DNS_TYPE_SRV       33U
//#define EHIP_DNS_TYPE_TXT       16U


#define EHIP_DNS_A_RR_IP_COUNT (sizeof(char*)/sizeof(ipv4_addr_t))
#define EHIP_DNS_CNAME_RR_DOMAIN_LEN_MAX (255U)
struct dns_entry{
    union{
        struct{
            ipv4_addr_t  ip[EHIP_DNS_A_RR_IP_COUNT];
        }a;
        struct{
            char        *domain;
        }cname;
    }rr;
};

EH_EXTERN_SIGNAL(signal_dns_table_changed);

/**
 * @brief                   DNS query function, 异步函数
 * @param  name             DNS query name
 * @param  old_desc_or_minus 旧的dns查询描述符，或者-1表示新查询
 * @return int              成功返回dns索引值，供查询使用，失败返回负数
 */
extern int ehip_dns_query_async(const char *name, int old_desc_or_minus, uint32_t type);

/**
 * @brief                   查找DNS查询条目,在调用ehip_dns_query_async后使用
 * @param  desc             DNS query descriptor, 由ehip_dns_query_async返回
 * @param  dname            DNS query name, 必须与ehip_dns_query_async中的name相同
 * @param  type             DNS query type, 必须与ehip_dns_query_async中的type相同
 * @return struct dns_entry* 返回值由 eh_ptr_to_error 进行错误码判断,成功返回dns条目指针，失败返回错误码负值
 *                              EH_RET_INVALID_PARAM: 一般为参数错误
 *                              EH_RET_AGAIN: 意味着正在查询
 *                              EH_RET_FAULT: 查询失败
 */
extern struct dns_entry* ehip_dns_find_entry(int desc, const char *dname, uint32_t type);

/**
 * @brief                   DNS set server function, 设置DNS服务器地址
 * @param  server           IPv4 address array of DNS server
 * @param  server_count     Number of DNS server
 * @return int              0成功，负数失败
 */
extern int ehip_dns_set_server(ipv4_addr_t *server, size_t server_count);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _DNS_H_