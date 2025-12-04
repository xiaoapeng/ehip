/**
 * @file dns.c
 * @brief DNS protocol implementation
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-11-23
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */

#include <eh.h>
#include <eh_types.h>
#include <eh_debug.h>
#include <eh_mem.h>
#include <eh_error.h>
#include <eh_signal.h>
#include <ehip_conf.h>
#include <ehip_core.h>
#include <ehip_module.h>
#include <ehip-ipv4/udp.h>

#include <ehip-protocol/dns.h>



struct __packed dns_hdr {
    uint16_t  id;
    union{
        struct{
#ifdef __BYTE_ORDER_LITTLE_ENDIAN__
            uint16_t    rd:1,
                        tc:1,
                        aa:1,
                        opcode:4,
                        qr:1,
                        rcode:4,
                        zero:3,
                        ra:1;
#else
            uint16_t    qr:1,
                        opcode:4,
                        aa:1,
                        tc:1,
                        rd:1,
                        ra:1,
                        zero:3,
                        rcode:4;
#endif
        };
        uint16_be_t  flags;
    };
    uint16_be_t     qdcount;
    uint16_be_t     ancount;
    uint16_be_t     nscount;
    uint16_be_t     arcount;
};

struct dns_entry_private {
    char             *name;
    struct dns_entry entry;
    uint16_t         ttl_or_query_time;
    uint16_t          type;
    uint8_t          id;
    uint8_t          retry_countdown;
    
#define EHIP_DNS_STATE_INIT     0U
#define EHIP_DNS_STATE_QUERYING 1U
#define EHIP_DNS_STATE_DONE     2U
#define EHIP_DNS_STATE_FAILED   3U

    uint8_t          state;                 /* EHIP_DNS_STATE_XX */
    uint8_t          query_server_map;      /* 当全部服务器查询失败时 query_server_map 将为0，此时设置state为 EHIP_DNS_STATE_FAILED */
};

#define DNS_DEFAULT_PORT            (53)
#define DNS_QUERY_TIMEOUT           3U
#define DNS_QUERY_RETRY_COUNT       5U
#define DNS_MAX_LABEL_LEN           (63)

#ifndef EH_DBG_MODEULE_LEVEL_DNS 
#define EH_DBG_MODEULE_LEVEL_DNS EH_DBG_INFO
#endif

eh_static_assert(EHIP_DNS_MAX_SERVER_COUNT < 8, "EHIP_DNS_MAX_SERVER_COUNT must be less than 8");

EH_DEFINE_SIGNAL(signal_dns_table_changed);

static ipv4_addr_t s_dns_server[EHIP_DNS_MAX_SERVER_COUNT];
static size_t s_dns_server_count = 0;
struct dns_entry_private s_dns_table[EHIP_DNS_MAX_TABLE_ENTRY_COUNT];
static udp_pcb_t s_udp_pcb = NULL;

#define dns_entry_is_used(entry) ((entry)->name != NULL)

static int _ehip_dns_query_async(int idx, const char *dname, size_t l);

static void dns_entry_destroy(struct dns_entry_private *entry){
    if(entry->name == NULL)
        return ;
    eh_free(entry->name);
    entry->name = NULL;
}

static int dns_entry_create(struct dns_entry_private *entry, const char *dname, size_t l, uint16_t type){
    if(type == EHIP_DNS_TYPE_CNAME){
        entry->name = eh_malloc(l + 1 + EHIP_DNS_CNAME_RR_DOMAIN_LEN_MAX + 1);
    }else{
        entry->name = eh_malloc(l + 1);
    }
    if(entry->name == NULL)
        return EH_RET_MALLOC_ERROR;
    strncpy(entry->name, dname, l);
    entry->name[l] = '\0';
    entry->type = type;
    entry->state = EHIP_DNS_STATE_INIT;
    entry->ttl_or_query_time = DNS_QUERY_TIMEOUT;
    entry->retry_countdown = DNS_QUERY_RETRY_COUNT;
    entry->query_server_map = 0;
    if(type == EHIP_DNS_TYPE_CNAME){
        entry->entry.rr.cname.domain = entry->name + l + 1;
        entry->entry.rr.cname.domain[0] = '\0';
    }else{
        memset(&entry->entry.rr.a, 0, sizeof(entry->entry.rr.a));
    }

    return 0;
}


static void slot_function_dns_1s_timer_handle(eh_event_t *e, void *slot_param){
    (void)e;
    (void)slot_param;
    int ret;
    for(size_t i = 0; i < EHIP_DNS_MAX_TABLE_ENTRY_COUNT; i++){
        struct dns_entry_private *entry = &s_dns_table[i];
        if(entry->name == NULL)
            continue;
        entry->ttl_or_query_time--;
        if(entry->ttl_or_query_time <= 0){
            if(entry->state == EHIP_DNS_STATE_QUERYING){
                entry->retry_countdown--;
                entry->ttl_or_query_time = (uint16_t)(DNS_QUERY_TIMEOUT << (DNS_QUERY_RETRY_COUNT - entry->retry_countdown));
                if(entry->retry_countdown > 0){
                    entry->id++;
                    ret = _ehip_dns_query_async((int)i, entry->name, strlen(entry->name));
                    if(ret == 0)
                        continue;
                }
                
            }
            dns_entry_destroy(entry);
            eh_signal_notify(&signal_dns_table_changed);
        }
    }
}

static EH_DEFINE_SLOT(slot_timer, slot_function_dns_1s_timer_handle, NULL);

static void udp_recv_callback(udp_pcb_t pcb, ipv4_addr_t addr, uint16_be_t port, struct ip_message *udp_rx_meg){
    (void) pcb;
    size_t server_idx;
    struct dns_hdr dns_hdr;
    int ret;
    uint8_t idx, id;
    char *cmp_pos;
    char tmp_buf[64];  /* 域名每一段label的最大长度为63字节 */
    char *tmp_buf_ptr; /* 可以在一些情况下进行0拷贝优化 */
    uint8_t label_len;
    struct dns_entry_private *entry;
    int  a_count = 0;
    int ancount = 0;
    uint32_t min_ttl = UINT32_MAX;
    for(server_idx = 0; server_idx < s_dns_server_count; server_idx++){
        if(addr == s_dns_server[server_idx]){
            break;
        }
    }

    if(server_idx == s_dns_server_count){
        eh_mwarnfl(DNS, "recv dns response from unknown server ip:" IPV4_FORMATIO ":%d", 
            ipv4_formatio(addr), eh_ntoh16(port));
        return ;
    }
    /* 解析DNS响应 */
    ret = ip_message_rx_real_read(udp_rx_meg, (uint8_t *)&dns_hdr, sizeof(struct dns_hdr));
    if(ret != sizeof(struct dns_hdr)){
        eh_mwarnfl(DNS, "recv dns response header size error, expect: %d, actual: %d", sizeof(struct dns_hdr), ret);
        return ;
    }

    id = (uint8_t)(dns_hdr.id >> 8);
    idx = (uint8_t)(dns_hdr.id & 0xff);
    eh_mdebugfl(DNS, "dns response id: %d, idx:%d , qr: %d, opcode: %d, aa: %d, tc: %d, rd: %d, ra: %d, rcode: %d",
        id, idx, dns_hdr.qr, dns_hdr.opcode, dns_hdr.aa, dns_hdr.tc, dns_hdr.rd, dns_hdr.ra, dns_hdr.rcode);
    eh_mdebugfl(DNS, "qdcount: %d, ancount: %d, nscount: %d, arcount: %d",
        eh_ntoh16(dns_hdr.qdcount), eh_ntoh16(dns_hdr.ancount), eh_ntoh16(dns_hdr.nscount), eh_ntoh16(dns_hdr.arcount));
    eh_mdebugfl(DNS, "msglen:%d |%.*hhq|",ip_message_rx_data_size(udp_rx_meg), 
         ehip_buffer_get_payload_size(udp_rx_meg->buffer), ehip_buffer_get_payload_ptr(udp_rx_meg->buffer));
    if(dns_hdr.qr == 0 || dns_hdr.qdcount != eh_ntoh16((uint16_t)1) || idx > EHIP_DNS_MAX_TABLE_ENTRY_COUNT || s_dns_table[idx].id != id){
        eh_mwarnfl(DNS, "Discard dns response id: %d, idx:%d , qr: %d, opcode: %d," EH_DEBUG_ENTER_SIGN
                        "       aa: %d, tc: %d, rd: %d, ra: %d, rcode: %d," EH_DEBUG_ENTER_SIGN
                        "       qdcount: %d , ancount: %d, nscount: %d, arcount: %d",
                        id, idx, dns_hdr.qr, dns_hdr.opcode, 
                        dns_hdr.aa, dns_hdr.tc, dns_hdr.rd, dns_hdr.ra, dns_hdr.rcode, 
                        eh_ntoh16(dns_hdr.qdcount), eh_ntoh16(dns_hdr.ancount), 
                        eh_ntoh16(dns_hdr.nscount), eh_ntoh16(dns_hdr.arcount));
        
        return ;
    }
    /* 对比问题是不是所查询的name */
    entry = &s_dns_table[idx];
    if(!dns_entry_is_used(entry) || entry->state != EHIP_DNS_STATE_QUERYING)
        return ;

    cmp_pos = entry->name;
    for(;;){
        ret = ip_message_rx_real_read(udp_rx_meg, &label_len, 1);
        if(ret != 1 ){
            eh_mwarnfl(DNS, "Discard dns response label len read error");
            return ;
        }
        if(label_len > DNS_MAX_LABEL_LEN){
            eh_mwarnfl(DNS, "Discard dns response label len %d > max len " EH_STRINGIFY(DNS_MAX_LABEL_LEN), label_len);
            return ;
        }
        if(label_len == 0){
            if(entry->name == cmp_pos || *(cmp_pos-1) != '\0'){
                eh_mwarnfl(DNS, "Discard dns response domain string not match %s", entry->name);
                return ;
            }
            break;
        }
        ret = ip_message_rx_read(udp_rx_meg, (uint8_t ** )&tmp_buf_ptr, label_len, (uint8_t*)tmp_buf);
        if(ret != label_len){
            eh_mwarnfl(DNS, "Discard dns response label read error");
            return ;
        }
        if(strncmp(tmp_buf_ptr, cmp_pos, label_len) != 0){
            eh_mwarnfl(DNS, "Discard dns response domain string not match %s", entry->name);
            return ;
        }
        cmp_pos += label_len + 1;
    }

    /* 检查 type 和class是否匹配 */
    {
        struct __packed {
            uint16_be_t type;
            uint16_be_t class;
        }qd;
        ret = ip_message_rx_real_read(udp_rx_meg, (uint8_t *)&qd, sizeof(qd));
        if(ret != sizeof(qd)){
            eh_mwarnfl(DNS, "Discard dns response qd type class read error");
            return ;
        }
        if(qd.type != eh_hton(entry->type) || qd.class != eh_hton((uint16_t)0x0001)){
            eh_mwarnfl(DNS, "Discard dns response qd type %d class %d not match %d 1", 
                eh_ntoh16(qd.type), eh_ntoh16(qd.class), eh_ntoh16(entry->type));
            return ;
        }
    }

    /* 检查rcode */
    if(dns_hdr.rcode != 0 || dns_hdr.ancount == 0){
        eh_mdebugfl(DNS, "Discard dns response rcode %d %d", dns_hdr.rcode, eh_ntoh16(dns_hdr.ancount));
        goto error;
    }
    
    /* 检查 answer section */
    for(ancount = eh_ntoh16(dns_hdr.ancount); ancount > 0; ancount--){
        uint8_t label_flag;
        struct __packed {
            uint16_be_t type;
            uint16_be_t class;
            uint32_be_t ttl;
            uint16_be_t rdlength;
        }an;
        ret = ip_message_rx_real_read(udp_rx_meg, &label_flag, 1);
        if(ret != 1)
            goto msg_incomplete;
        if(label_flag < 0x3F){
            /* 可以跳过其中的域名，因为我们就一个问题，在标准情况下它必然是我们查询的name */
            while(label_flag != 0){
                ret = ip_message_rx_read_skip(udp_rx_meg, label_flag);
                if(ret != label_flag)
                    goto msg_incomplete;
                ret = ip_message_rx_real_read(udp_rx_meg, &label_flag, 1);
                if(ret != 1)
                    goto msg_incomplete;
            }
        }else if(label_flag < 0xC0){
            eh_mwarnfl(DNS, "Discard dns response label flag %d not support", label_flag);
            goto error;
        }else {
            /* 压缩指针，我们只有一个问题，所以指针只能指向我们查询的name，这里默认不解析 */
            ret = ip_message_rx_read_skip(udp_rx_meg, 1);
            if(ret != 1)
                goto msg_incomplete;
        }
        /* 解析 type 和 class */
        ret = ip_message_rx_real_read(udp_rx_meg, (uint8_t *)&an, sizeof(an));
        if(ret != sizeof(an)){
            eh_mwarnfl(DNS, "Discard dns response an type class read error");
            return ;
        }
        if(an.type != eh_hton(entry->type) || an.class != eh_hton((uint16_t)0x0001)){
            /* 直接跳过这个答案，不是我们想要的 */
            goto skip;
        }

        if(an.type == eh_hton((uint16_t)EHIP_DNS_TYPE_A)){
            ipv4_addr_t tmp_ip;
            if(eh_ntoh16(an.rdlength) != 4){
                eh_mwarnfl(DNS, "Discard dns response an type A rdlength %d not 4", eh_ntoh16(an.rdlength));
                goto msg_incomplete;
            }
            if(a_count >= (int)EHIP_DNS_A_RR_IP_COUNT)
                goto skip;
            /* 记录最小的ttl */
            if(eh_ntoh32(an.ttl) < min_ttl){
                min_ttl = eh_ntoh32(an.ttl);
            }
            ret = ip_message_rx_real_read(udp_rx_meg, (uint8_t *)&tmp_ip, 4);
            if(ret != 4){
                eh_mwarnfl(DNS, "Discard dns response an type A ip read error");
                goto msg_incomplete;
            }
            entry->entry.rr.a.ip[a_count++] = tmp_ip;
        }else if(an.type == eh_hton((uint16_t)EHIP_DNS_TYPE_CNAME)) {
            uint8_t label_len;
            uint16_t cname_len = eh_ntoh16(an.rdlength);
            char *domain_write_pos = entry->entry.rr.cname.domain;
            if(cname_len > EHIP_DNS_CNAME_RR_DOMAIN_LEN_MAX + 2){
                eh_mwarnfl(DNS, "Discard dns response an type CNAME rdlength %d > max len  " EH_STRINGIFY(EHIP_DNS_CNAME_RR_DOMAIN_LEN_MAX), eh_ntoh16(an.rdlength));
                goto skip;
            }
            if(cname_len == 0 || domain_write_pos[0]){
                goto skip;
            }
            while(cname_len){
                ret = ip_message_rx_real_read(udp_rx_meg, &label_len, 1);
                if(ret != 1)
                    goto msg_incomplete;
                cname_len --;
                if(label_len == 0)
                    break;
                if(label_len > DNS_MAX_LABEL_LEN || (uint16_t)label_len > cname_len)
                    goto msg_incomplete;
                ret = ip_message_rx_real_read(udp_rx_meg, (uint8_t*)domain_write_pos, label_len);
                if(ret != label_len)
                    goto msg_incomplete;
                cname_len -= label_len;
                domain_write_pos += label_len;
                *domain_write_pos++ = '.';
            }
            /* 记录最小的ttl */
            if(eh_ntoh32(an.ttl) < min_ttl){
                min_ttl = eh_ntoh32(an.ttl);
            }
            if(cname_len){
                /* 读掉剩下无用的字节 */
                ret = ip_message_rx_read_skip(udp_rx_meg, cname_len);
                if(ret != cname_len)
                    goto msg_incomplete;
            }
            *domain_write_pos = '\0';
        }else{
            goto skip;
        }

        /* END */
        continue;
    skip:
        ret = ip_message_rx_read_skip(udp_rx_meg, eh_ntoh16(an.rdlength));
        if(ret != eh_ntoh16(an.rdlength))
            goto msg_incomplete;
    }
    if(a_count || entry->entry.rr.cname.domain[0]){
        entry->state = EHIP_DNS_STATE_DONE;
        if(min_ttl > UINT16_MAX){
            entry->ttl_or_query_time = UINT16_MAX;
        }else{
            entry->ttl_or_query_time = (uint16_t)min_ttl;
        }
        eh_signal_notify(&signal_dns_table_changed);
        return ;
    }
msg_incomplete:
    eh_mwarnfl(DNS, "Discard dns response message incomplete");
error:
    entry->query_server_map &= (uint8_t)(~(1U << server_idx));
    if(entry->query_server_map == 0){
        entry->state = EHIP_DNS_STATE_FAILED;
        entry->ttl_or_query_time = UINT16_MAX;
        eh_signal_notify(&signal_dns_table_changed);
    }
    return ;
}

static int dns_udp_sender_mkquery(udp_pcb_t pcb, struct udp_sender *udp_sender, ipv4_addr_t dns_server, uint16_be_t dns_port, 
        uint16_t id, const char *dname, size_t dname_len ,uint8_t op, uint16_t type, uint16_t class){
    int ret = 0;
    ehip_buffer_t *out_buffer = NULL;
    struct dns_hdr *dns_hdr;
    ehip_buffer_size_t out_buffer_capacity_size = 0;
    ehip_buffer_size_t pack_size;
    char *question;
    size_t m,j;
    ehip_udp_sender_init(pcb, udp_sender, dns_server, dns_port);
    ret = ehip_udp_sender_route_ready(udp_sender);
    if(ret < 0){
        eh_mwarnfl(DNS, "dns server " IPV4_FORMATIO ":%d udp sender route fail %d", 
            ipv4_formatio(dns_server), eh_ntoh16(dns_port), ret);
        return ret;
    }
    ret = ehip_udp_sender_add_buffer(udp_sender, &out_buffer, &out_buffer_capacity_size);
    if(ret < 0){
        eh_merrfl(DNS, "dns server " IPV4_FORMATIO ":%d udp sender add buffer fail %d", 
            ipv4_formatio(dns_server), eh_ntoh16(dns_port), ret);
        return ret;
    }
    /* 检查缓冲区是否足够  最小需要 sizeof(struct dns_hdr) + 1 + l + 1 + type + class */
    pack_size = (ehip_buffer_size_t)(sizeof(struct dns_hdr) + 1 + dname_len + 1 + 2 + 2);
    if(out_buffer_capacity_size < pack_size){
        eh_merrfl(DNS, "dns server " IPV4_FORMATIO ":%d udp sender buffer size %d < %d", 
            ipv4_formatio(dns_server), out_buffer_capacity_size, pack_size);
        ehip_udp_sender_deinit(udp_sender);
        return ret;
    }
    dns_hdr = (struct dns_hdr *)ehip_buffer_payload_append(out_buffer, pack_size);
    memset(dns_hdr, 0, sizeof(struct dns_hdr));
    dns_hdr->id = id;
    dns_hdr->opcode = (uint8_t)(op & 0x0f);
    dns_hdr->rd = 1;
    dns_hdr->qdcount = eh_hton16(1);
    question = (char *)(dns_hdr + 1);
    memcpy(question + 1, dname, dname_len+1);
    for(m = 1; m < (dname_len + 1); m = j+1){
        for(j = m; question[j] && question[j] != '.'; j++)
            ;
        if (j-m > DNS_MAX_LABEL_LEN){
            eh_mwarnfl(DNS, "dns label %.*s is too long", j - m, question + m);
            ehip_udp_sender_deinit(udp_sender);
            ret = EH_RET_INVALID_PARAM;
            return ret;
        }
        question[m-1] = (char)(j - m);
    }
    question[m + 0] = (char)(type >> 8);
    question[m + 1] = (char)(type & 0xff);
    question[m + 2] = (char)(class >> 8);
    question[m + 3] = (char)(class & 0xff);
    eh_debugfl("dns query |%.*hhq|", pack_size, dns_hdr);
    return 0;
}

static inline int dns_udp_sender_clean(struct udp_sender *udp_sender){
    ehip_udp_sender_deinit(udp_sender);
    return 0;
}

static inline int dns_udp_pcb_try_init(void){
    int ret = 0;
    if(s_udp_pcb == NULL){
        s_udp_pcb = ehip_udp_any_new(0);
        if (eh_ptr_to_error(s_udp_pcb) < 0) {
            eh_merrfl(DNS, "udp pcb create fail %d", eh_ptr_to_error(s_udp_pcb));
            ret = eh_ptr_to_error(s_udp_pcb);
            return ret;
        }
        ehip_udp_set_recv_callback(s_udp_pcb, udp_recv_callback);
    }
    return 0;
}

static int _ehip_dns_query_async(int idx, const char *dname, size_t l){
    int ret = 0;
    struct dns_entry_private *entry;
    entry = &s_dns_table[idx];
    struct udp_sender udp_sender;
    int send_cnt = 0;
    
    for(size_t i = 0; i < s_dns_server_count; i++){
        ret = dns_udp_sender_mkquery(s_udp_pcb, &udp_sender, s_dns_server[i], 
            eh_hton16(DNS_DEFAULT_PORT), (uint16_t)((entry->id << 8) | idx), 
            dname, l, 0, entry->type, 1);
        if(ret < 0){
            if(ret == EH_RET_INVALID_PARAM)
                return ret;
        }
        ret = ehip_udp_send(s_udp_pcb, &udp_sender);
        dns_udp_sender_clean(&udp_sender);
        if(ret < 0){
            eh_mwarnfl(DNS, "dns server %d udp send fail %d", i, ret);
            continue;
        }
        entry->query_server_map |= (1U << i);
        send_cnt ++;
    }
    if(send_cnt == 0){
        eh_mwarnfl(DNS, "dns server send fail");
        if(ret == 0)
            ret = EH_RET_INVALID_STATE;
        return ret;
    }
    return 0;
}

static int _ehip_dns_find_entry(int old_desc, const char *dname, size_t l, uint32_t type){
    struct dns_entry_private *entry;
    if(old_desc < 0 || old_desc >= (int)EHIP_DNS_MAX_TABLE_ENTRY_COUNT)
        return EH_RET_INVALID_PARAM;
    entry = &s_dns_table[old_desc];
    if( dns_entry_is_used(entry) &&
        (uint32_t)entry->type == type &&
        strncmp(entry->name, dname, l) == 0){
        return old_desc;
    }
    return EH_RET_NOT_EXISTS;
}


int ehip_dns_query_async(const char *dname, int old_desc_or_minus, uint32_t type){
	size_t l = strnlen(dname, 255);
	int i;
    int idx = -1,ret = 0;
    int null_idx = -1;
    int earliest_idx = -1;
    uint16_t earliest_ttl = 0xFFFF;
    struct dns_entry_private *entry;
    if(type != EHIP_DNS_TYPE_A && type != EHIP_DNS_TYPE_CNAME)
            return EH_RET_INVALID_PARAM;

	if (l && dname[l-1]=='.') l--;
	if (l && dname[l-1]=='.') return EH_RET_INVALID_PARAM;
    if (l == 0)               return EH_RET_INVALID_PARAM;
    if(s_dns_server_count == 0){
        eh_mwarnfl(DNS, "no dns server set");
        return EH_RET_INVALID_STATE;
    }
    /* 遍历数组，查找是否有相同的域名 */
    idx = _ehip_dns_find_entry(old_desc_or_minus, dname, l, type);
    if(idx >= 0){
        entry = &s_dns_table[idx];
        goto found_idx;
    }
    for(i=0; i < (int)EHIP_DNS_MAX_TABLE_ENTRY_COUNT; i++){
        entry = &s_dns_table[i];
        if(!dns_entry_is_used(entry)){
            if(null_idx == -1)
                null_idx = i;
            continue;
        }
        if((uint32_t)entry->type == type &&
            strncmp(entry->name, dname, l) == 0){
            idx = i;
            goto found_idx;
        }
        if(null_idx == -1 && entry->state == EHIP_DNS_STATE_DONE && entry->ttl_or_query_time < earliest_ttl){
            earliest_idx = i;
            earliest_ttl = entry->ttl_or_query_time;
        }
    }
    if(null_idx == -1 && earliest_idx == -1){
        eh_mwarnfl(DNS, "dns table is full");
        return EH_RET_BUSY;
    }
    if(earliest_idx == -1){
        idx = null_idx;
        entry = &s_dns_table[idx];
    }else{
        idx = earliest_idx;
        entry = &s_dns_table[idx];
        dns_entry_destroy(entry);
    }
    ret = dns_entry_create(entry, dname, l, (uint16_t)type);
    if(ret < 0)
        return ret;
found_idx:
    if(entry->state == EHIP_DNS_STATE_DONE || entry->state == EHIP_DNS_STATE_QUERYING)
        return idx;
    dns_udp_pcb_try_init();
    entry->id++;
    entry->state = EHIP_DNS_STATE_QUERYING;
    ret = _ehip_dns_query_async(idx, dname, l);
    if(ret < 0){
        dns_entry_destroy(entry);
        return ret;
    }

    return idx;
}

struct dns_entry* ehip_dns_find_entry(int desc, const char *dname, uint32_t type){
    size_t l = strnlen(dname, 255);
    struct dns_entry_private *entry;
    int idx;
	if (l && dname[l-1]=='.') l--;
	if (l && dname[l-1]=='.') return eh_error_to_ptr(EH_RET_INVALID_PARAM);
    idx = _ehip_dns_find_entry(desc, dname, l, type);
    if(idx < 0)
        return eh_error_to_ptr(idx);
    entry = &s_dns_table[idx];
    if(entry->state == EHIP_DNS_STATE_DONE)
        return &entry->entry;
    if(entry->state == EHIP_DNS_STATE_QUERYING)
        return eh_error_to_ptr(EH_RET_AGAIN);
    return eh_error_to_ptr(EH_RET_FAULT);
}

int ehip_dns_set_server(ipv4_addr_t *server, size_t server_count){
    if(server_count > EHIP_DNS_MAX_SERVER_COUNT){
        eh_mwarnfl(DNS, "server_count %d > EHIP_DNS_MAX_SERVER_COUNT %d", server_count, EHIP_DNS_MAX_SERVER_COUNT);
        server_count = EHIP_DNS_MAX_SERVER_COUNT;
    }
    memcpy(s_dns_server, server, server_count * sizeof(ipv4_addr_t));
    s_dns_server_count = server_count;
    return 0;
}

static int __init dns_init(void){
    memset(&s_dns_table, 0, sizeof(s_dns_table));
    eh_signal_slot_connect_to_main(&signal_ehip_timer_1s, &slot_timer);
    eh_signal_init(&signal_dns_table_changed);
    return 0;
}

static void __exit dns_exit(void){
    for(size_t i = 0; i < EHIP_DNS_MAX_TABLE_ENTRY_COUNT; i++){
        dns_entry_destroy(&s_dns_table[i]);
    }
    if(s_udp_pcb != NULL){
        ehip_udp_delete(s_udp_pcb);
        s_udp_pcb = NULL;
    }
    
    eh_signal_slot_disconnect_from_main(&signal_ehip_timer_1s, &slot_timer);
}

ehip_app_protocol_module_export(dns_init, dns_exit);
