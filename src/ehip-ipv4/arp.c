/**
 * @file arp.c
 * @brief arp协议
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-11-13
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */


#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <eh.h>
#include <eh_debug.h>
#include <eh_types.h>
#include <eh_error.h>
#include <eh_swab.h>
#include <eh_signal.h>
#include <eh_timer.h>
#include <ehip_core.h>
#include <ehip-ipv4/route.h>
#include <ehip_netdev.h>
#include <ehip_module.h>
#include <ehip_buffer.h>
#include <ehip_netdev_type.h>
#include <ehip_protocol_handle.h>
#include <ehip_netdev_trait.h>
#include <ehip-ipv4/arp.h>
#include <ehip-ipv4/ip.h>
#include <ehip-mac/ethernet.h>

EH_DEFINE_SIGNAL(signal_arp_table_changed);
struct arp_entry _arp_table[EHIP_ARP_CACHE_MAX_NUM];
EH_DEFINE_STATIC_CUSTOM_SIGNAL(signal_timer_1s, eh_event_timer_t, EH_TIMER_INIT(signal_timer_1s.custom_event));

static int arp_send_dst(uint16_be_t type, enum ehip_ptype ptype, ehip_netdev_t *netdev, 
    const ehip_hw_addr_t *s_hw_addr, const ehip_hw_addr_t *d_hw_addr, 
    ipv4_addr_t s_ipv4_addr, ipv4_addr_t d_ipv4_addr, const ehip_hw_addr_t *target_hw_addr);

static int arp_request_dst(ehip_netdev_t *netdev, ipv4_addr_t ipv4_addr, const ehip_hw_addr_t *target_hw_addr);
static bool arp_state_is_change(uint8_t old_state, uint8_t new_state);
static bool arp_state_update_change_notify(int index, const ehip_hw_addr_t *new_hw_addr, uint8_t new_state);

static void slot_function_arp_1s_timer_handler(eh_event_t *e, void *slot_param){
    (void)e;
    (void)slot_param;
    int ret;
    // uint8_t old_state;
    struct arp_entry *arp_table_entry;
    for(size_t i=0; i<EHIP_ARP_CACHE_MAX_NUM; i++){
        arp_table_entry = &_arp_table[i];
        // old_state = arp_table_entry->state;
        switch (arp_table_entry->state){
            case ARP_STATE_NUD_FAILED:
                break;
            case ARP_STATE_NUD_STALE:
                if(arp_table_entry->delay_probe_time_cd){
                    arp_table_entry->delay_probe_time_cd--;
                    arp_state_update_change_notify((int)i, NULL, ARP_STATE_NUD_DELAY);
                }
                if(arp_table_entry->stale_time != 0xFFFF)
                    arp_table_entry->stale_time++;
                break;
            case ARP_STATE_NUD_INCOMPLETE:
            case ARP_STATE_NUD_PROBE:
                /* 
                 * 进行发送报文进行ARP查询 
                 * ARP_STATE_NUD_PROBE 使用单播
                 * ARP_STATE_NUD_INCOMPLETE 使用广播
                 */
                ret = arp_request_dst(arp_table_entry->netdev, arp_table_entry->ip_addr, 
                    arp_table_entry->state == ARP_STATE_NUD_INCOMPLETE ? NULL : &arp_table_entry->hw_addr);
                if(ret < 0)
                    arp_state_update_change_notify((int)i, NULL, ARP_STATE_NUD_FAILED);
                arp_table_entry->retry_cnt++;
                if(arp_table_entry->retry_cnt > EHIP_ARP_MAX_RETRY_CNT)
                    arp_state_update_change_notify((int)i, NULL, ARP_STATE_NUD_FAILED);
                break;
            case ARP_STATE_NUD_DELAY:
                /* 等待 delay_probe_time_cd 超时后迁移到 ARP_STATE_NUD_PROBE*/
                if(arp_table_entry->delay_probe_time_cd == 0 || --arp_table_entry->delay_probe_time_cd == 0 ){
                    ret = arp_request_dst(arp_table_entry->netdev, arp_table_entry->ip_addr, &arp_table_entry->hw_addr);
                    arp_state_update_change_notify((int)i, NULL, ret == 0 ? ARP_STATE_NUD_PROBE : ARP_STATE_NUD_FAILED);
                }
                break;
            case ARP_STATE_NUD_REACHABLE:
                /* 绝对信任状态 */
                if(arp_table_entry->delay_probe_time_cd)
                    arp_table_entry->delay_probe_time_cd--;
                if(arp_table_entry->reachable_time_cd == 0 || --arp_table_entry->reachable_time_cd == 0){
                    arp_state_update_change_notify((int)i, NULL, 
                        arp_table_entry->delay_probe_time_cd ? ARP_STATE_NUD_DELAY : ARP_STATE_NUD_STALE);
                }

                break;
        }
    }
}

EH_DEFINE_SLOT(slot_timer, slot_function_arp_1s_timer_handler, NULL);

/* 比较新旧状态，结果可以用来触发 signal_arptable_changed */
static bool arp_state_is_change(uint8_t old_state, uint8_t new_state){
    return  ( (old_state >= ARP_STATE_NUD_STALE && new_state < ARP_STATE_NUD_STALE) ||
              (old_state < ARP_STATE_NUD_STALE && new_state >= ARP_STATE_NUD_STALE)
            );
}

static bool arp_state_update_change_notify(int index, const ehip_hw_addr_t *new_hw_addr, uint8_t new_state){
    bool is_change;
    struct arp_entry *arp_table_entry = &_arp_table[index];
    uint8_t old_state = arp_table_entry->state;

    if(old_state != new_state){
        switch ((enum etharp_state)new_state) {
            case ARP_STATE_NUD_INCOMPLETE:
                arp_table_entry->retry_cnt = 0;
                break;
            case ARP_STATE_NUD_STALE:
                arp_table_entry->delay_probe_time_cd = 0;
                arp_table_entry->reachable_time_cd = 0;
                break;
            case ARP_STATE_NUD_PROBE:
                arp_table_entry->retry_cnt = 0;
                break;
            case ARP_STATE_NUD_REACHABLE:
                arp_table_entry->reachable_time_cd = EHIP_ARP_REACHABLE_TIME;
                break;
            default:
                break;
        }
    }
    
    is_change = arp_state_is_change(arp_table_entry->state, new_state);
    arp_table_entry->state = new_state;

    if(new_hw_addr){
        if(is_change == false){
            for(int i=0; i<arp_table_entry->netdev->attr.hw_addr_len; i++){
                if(((uint8_t*)new_hw_addr)[i] != ((uint8_t*)&arp_table_entry->hw_addr)[i]){
                    is_change = true;
                    break;
                }
            }
        }
        memcpy(arp_table_entry->hw_addr.addr, new_hw_addr, arp_table_entry->netdev->attr.hw_addr_len);
    }
    if(is_change)
        eh_signal_notify(&signal_arp_table_changed);
    return is_change;
}




static int arp_send_dst(uint16_be_t type, enum ehip_ptype ptype, ehip_netdev_t *netdev, 
    const ehip_hw_addr_t *s_hw_addr, const ehip_hw_addr_t *d_hw_addr, 
    ipv4_addr_t s_ipv4_addr, ipv4_addr_t d_ipv4_addr, const ehip_hw_addr_t *target_hw_addr){
    int ret;
    struct ehip_buffer* newbuf;
    struct arp_hdr *arp_hdr;
    uint8_t *pos;
    if(s_hw_addr == NULL || netdev == NULL ) return EH_RET_INVALID_PARAM;
    newbuf = ehip_buffer_new(netdev->attr.buffer_type, netdev->attr.hw_head_size);
    if(eh_ptr_to_error(newbuf) < 0)
        return eh_ptr_to_error(newbuf);
    newbuf->netdev = netdev;
    arp_hdr = (struct arp_hdr*)ehip_buffer_payload_append(newbuf, (ehip_buffer_size_t)arp_hdr_len(netdev));
    if(arp_hdr == NULL){
        ret = EH_RET_INVALID_STATE;
        goto error;
    }
    if(target_hw_addr == NULL && (target_hw_addr = ehip_netdev_trait_broadcast_hw(netdev)) == NULL){
        ret = EH_RET_INVALID_STATE;
        goto error;
    }
    ret = ehip_netdev_trait_hard_header(netdev, newbuf, s_hw_addr, target_hw_addr, ptype, (ehip_buffer_size_t)arp_hdr_len(netdev));
    if(ret < 0)
        goto error;
    
    arp_hdr->ar_hrd = eh_hton16(netdev->type);
    arp_hdr->ar_pro = eh_hton16(EHIP_ETH_P_IP);

    arp_hdr->ar_op = type;
    arp_hdr->ar_hln = netdev->attr.hw_addr_len;
    arp_hdr->ar_pln = 4;

    pos = (uint8_t*)(arp_hdr + 1);
    memcpy(pos, s_hw_addr, netdev->attr.hw_addr_len);
    pos += netdev->attr.hw_addr_len;
    memcpy(pos, &s_ipv4_addr, 4);
    pos += 4;
    if(d_hw_addr){
        memcpy(pos, d_hw_addr, netdev->attr.hw_addr_len);
    }else{
        memset(pos, 0, netdev->attr.hw_addr_len);
    }
    pos += netdev->attr.hw_addr_len;
    memcpy(pos, &d_ipv4_addr, 4);

    ehip_queue_tx(newbuf);

    return 0;
error:
    ehip_buffer_free(newbuf);
    return ret;
}


static int arp_request_dst(ehip_netdev_t *netdev, ipv4_addr_t ipv4_addr, const ehip_hw_addr_t *target_hw_addr){
    if(netdev == NULL) return EH_RET_INVALID_PARAM;
    /* 进行发送报文进行ARP查询 */
    ipv4_addr_t s_ipv4_addr = ipv4_netdev_get_addr(ehip_netdev_trait_ipv4_dev(netdev));
    if(ipv4_is_zeronet(s_ipv4_addr)){
        return EH_RET_INVALID_STATE;
    }
    return arp_send_dst(
        eh_hton16(ARPOP_REQUEST), EHIP_PTYPE_ETHERNET_ARP, netdev, 
        ehip_netdev_trait_hw_addr(netdev), NULL,
        s_ipv4_addr, ipv4_addr, target_hw_addr );
}

static int arp_find_entry(ehip_netdev_t *netdev, ipv4_addr_t ip_addr, bool is_create){
    size_t i;
    int idx;
    int usable_failed_idx = -1;
    int usable_incomplete_state_idx = -1;
    int usable_stale_state_idx = -1;
    int usable_probe_state_idx = -1;
    int usable_delay_state_idx = -1;
    int usable_reachable_state_idx = -1;  /* 小值优先级高 */
    int usable_reachable2_state_idx = -1;  /* 小值优先级高  最近有在用的*/

    struct arp_entry *arp_table_entry;

    if(!is_create){
        for( i=0;i<EHIP_ARP_CACHE_MAX_NUM;i++ ){
            arp_table_entry = &_arp_table[i];
            if(arp_table_entry->state == ARP_STATE_NUD_FAILED)
                continue;
            if(arp_table_entry->ip_addr == ip_addr && arp_table_entry->netdev == netdev)
                return (int)i;
        }
        return EH_RET_NOT_EXISTS; 
    }

    for( i=0;i<EHIP_ARP_CACHE_MAX_NUM;i++ ){
        arp_table_entry = &_arp_table[i];
        if(arp_table_entry->state == ARP_STATE_NUD_FAILED){
            if(usable_failed_idx == -1) 
                usable_failed_idx = (int)i;
            continue;
        }
        if(arp_table_entry->ip_addr == ip_addr && arp_table_entry->netdev == netdev)
            return (int)i;
        switch (arp_table_entry->state) {
            case ARP_STATE_NUD_INCOMPLETE:{
                if(usable_incomplete_state_idx == -1 || arp_table_entry->retry_cnt > 
                    _arp_table[usable_incomplete_state_idx].retry_cnt)
                    usable_incomplete_state_idx = (int)i;
                break;
            }

            case ARP_STATE_NUD_STALE:{
                if(usable_stale_state_idx == -1 || arp_table_entry->stale_time > 
                    _arp_table[usable_stale_state_idx].stale_time)
                    usable_stale_state_idx = (int)i;
                break;
            }

            case ARP_STATE_NUD_PROBE:{
                if(usable_probe_state_idx == -1 || arp_table_entry->retry_cnt > 
                    _arp_table[usable_probe_state_idx].retry_cnt)
                    usable_probe_state_idx = (int)i;
                break;
            }

            case ARP_STATE_NUD_DELAY:{
                if(usable_delay_state_idx == -1 || arp_table_entry->delay_probe_time_cd < 
                    _arp_table[usable_delay_state_idx].delay_probe_time_cd)
                    usable_delay_state_idx = (int)i;
                break;
            }

            case ARP_STATE_NUD_REACHABLE:{
                if(arp_table_entry->delay_probe_time_cd > 0){
                    if(usable_reachable2_state_idx == -1 || arp_table_entry->delay_probe_time_cd < 
                        _arp_table[usable_reachable2_state_idx].delay_probe_time_cd)
                        usable_reachable2_state_idx = (int)i;
                }else{
                    if(usable_reachable_state_idx || arp_table_entry->reachable_time_cd < 
                        _arp_table[usable_reachable_state_idx].reachable_time_cd)
                        usable_reachable_state_idx = (int)i;
                }
                break;
            }

        }
    }

    /* 
     *   优先级排序:
     *   1.usable_failed_idx
     *   2.usable_stale_state_idx
     *   3.usable_reachable_state_idx
     *   4.usable_probe_state_idx
     *   5.usable_delay_state_idx
     *   6.usable_reachable2_state_idx
     *   7.usable_incomplete_state_idx
     */

    if(usable_failed_idx != -1){
        idx = usable_failed_idx;
        goto found;
    }
    if(usable_stale_state_idx != -1){
        idx = usable_stale_state_idx;
        goto found;
    }
    if(usable_reachable_state_idx != -1){
        idx =  usable_reachable_state_idx;
        goto found;
    }
    if(usable_probe_state_idx != -1){
        idx =  usable_probe_state_idx;
        goto found;
    }
    if(usable_delay_state_idx != -1){
        idx =  usable_delay_state_idx;
        goto found;
    }
    if(usable_reachable2_state_idx != -1){
        idx =  usable_reachable2_state_idx;
        goto found;
    }
    if(usable_incomplete_state_idx != -1){
        idx =  usable_incomplete_state_idx;
        goto found;
    }

    return -1;
found:
    _arp_table[idx].ip_addr = ip_addr;
    _arp_table[idx].netdev = netdev;
    arp_state_update_change_notify(idx, NULL, ARP_STATE_NUD_NONE);
    return idx;
}

static void arp_handle(struct ehip_buffer* buf){
    const struct arp_hdr *arp_hdr;
    const char *arp_pos;
    const ehip_hw_addr_t *s_hw_addr, *d_hw_addr;
    ipv4_addr_t s_ipv4_addr, d_ipv4_addr;
    struct ipv4_netdev* ipv4_dev;
    int arp_entry_idx;
    
    ipv4_dev = ehip_netdev_trait_ipv4_dev(buf->netdev);
    
    if( ipv4_dev == NULL || 
        ehip_buffer_get_payload_size(buf) < arp_hdr_len(buf->netdev) || 
        !ipv4_netdev_flags_is_arp_support(ipv4_dev)  ){
        goto drop;
    }
    arp_hdr = (const struct arp_hdr *)ehip_buffer_get_payload_ptr(buf);
    if(arp_hdr->ar_hln != buf->netdev->attr.hw_addr_len || arp_hdr->ar_pln != 4){
        goto drop;
    }
    
    /* 处理 arp */
    switch (buf->netdev->type) {
        case EHIP_NETDEV_TYPE_ETHERNET:
            if( (arp_hdr->ar_hrd != eh_hton16(EHIP_ARP_ETHER) && 
                arp_hdr->ar_hrd != eh_hton16(EHIP_ARP_IEEE802) ) ||
                arp_hdr->ar_pro != eh_hton16(EHIP_ETH_P_IP)
               )
                goto drop;
            break;
        default: 
            goto drop;
    }

    if(arp_hdr->ar_op != eh_hton16(ARPOP_REPLY) && arp_hdr->ar_op != eh_hton16(ARPOP_REQUEST)) 
        goto drop;

    /* s_hw */
    arp_pos = (const char *)(arp_hdr + 1);
    s_hw_addr = (const ehip_hw_addr_t *)arp_pos;
    
    /* s_ip */
    arp_pos += arp_hdr->ar_hln;
    memcpy(&s_ipv4_addr, arp_pos, sizeof(ipv4_addr_t));

    /* d_hw */
    arp_pos += sizeof(ipv4_addr_t);
    d_hw_addr = (const ehip_hw_addr_t *)arp_pos;
    
    /* d_ip */
    arp_pos += arp_hdr->ar_hln;
    memcpy(&d_ipv4_addr, arp_pos, sizeof(ipv4_addr_t));

    eh_debugfl("ar_hrd: %04hx", arp_hdr->ar_hrd);
    eh_debugfl("ar_pro: %04hx", arp_hdr->ar_pro);
    eh_debugfl("ar_hln: %02hhx", arp_hdr->ar_hln);
    eh_debugfl("ar_pln: %02hhx", arp_hdr->ar_pln);
    eh_debugfl("ar_op: %04hx", arp_hdr->ar_op);
    eh_debugfl("s_hw: %.*hhq", arp_hdr->ar_hln, s_hw_addr);
    eh_debugfl("s_ip: %d.%d.%d.%d", 
        ipv4_addr_to_dec0(s_ipv4_addr), ipv4_addr_to_dec1(s_ipv4_addr),
        ipv4_addr_to_dec2(s_ipv4_addr), ipv4_addr_to_dec3(s_ipv4_addr));
    eh_debugfl("d_hw: %.*hhq", arp_hdr->ar_hln, d_hw_addr);
    eh_debugfl("d_ip: %d.%d.%d.%d", 
        ipv4_addr_to_dec0(d_ipv4_addr), ipv4_addr_to_dec1(d_ipv4_addr),
        ipv4_addr_to_dec2(d_ipv4_addr), ipv4_addr_to_dec3(d_ipv4_addr));

	if(eh_unlikely(ipv4_is_multicast(d_ipv4_addr)))
        goto drop;

    /* 忽略免费ARP */
    if( s_ipv4_addr == d_ipv4_addr )
        goto drop;

    /* 
     * 查路由表看是否接受这个arp包 d_ipv4_addr 是否接受 
     * ARP协议不接受任何转发
     */
    /* 请求 */
    if( arp_hdr->ar_op == eh_hton16(ARPOP_REQUEST) && 
        ( ( ipv4_route_input(s_ipv4_addr, d_ipv4_addr, buf->netdev, NULL) == ROUTE_TABLE_LOCAL_SELF) ||
          ( s_ipv4_addr == 0 && ipv4_netdev_is_ipv4_addr_valid(ipv4_dev, d_ipv4_addr))
        )
    ){
        arp_send_dst(eh_hton16(ARPOP_REPLY), (uint16_t)EHIP_PTYPE_ETHERNET_ARP, buf->netdev, 
            ehip_netdev_trait_hw_addr(buf->netdev), s_hw_addr, 
            d_ipv4_addr, s_ipv4_addr, s_hw_addr);
        /* 创建且更新此条目，设置为ARP_STATE_NUD_STALE状态 */
        if(s_ipv4_addr){
            arp_entry_idx = arp_find_entry(buf->netdev, s_ipv4_addr, true);
            if(arp_entry_idx >= 0)
                arp_state_update_change_notify(arp_entry_idx, s_hw_addr, ARP_STATE_NUD_STALE);
        }
        goto consume;
    }

    if( arp_hdr->ar_op == eh_hton16(ARPOP_REPLY) &&
        ipv4_route_input(s_ipv4_addr, d_ipv4_addr, buf->netdev, NULL) == ROUTE_TABLE_LOCAL_SELF
    ){
        /* 处理ARPOP_REPLY*/
        /* 查看此条目是否存在，若不存在则忽略该报文*/
        arp_entry_idx = arp_find_entry(buf->netdev, s_ipv4_addr, false);
        if(arp_entry_idx < 0) goto drop;
        arp_state_update_change_notify(arp_entry_idx, s_hw_addr, ARP_STATE_NUD_REACHABLE);
    }

consume:
drop:
    ehip_buffer_free(buf);
}

int arp_query(const ehip_netdev_t *netdev, const ipv4_addr_t ip_addr, int old_idx_or_minus){
    int idx;
    if(old_idx_or_minus >= 0 && old_idx_or_minus < (int)EHIP_ARP_CACHE_MAX_NUM && 
        _arp_table[old_idx_or_minus].ip_addr == ip_addr && _arp_table[old_idx_or_minus].netdev == netdev && 
        _arp_table[old_idx_or_minus].state != ARP_STATE_NUD_FAILED){
        idx = old_idx_or_minus;
        goto valid;
    }
    /* 遍历整个表进行寻找，找不到就进行创建 */
    idx = arp_find_entry((ehip_netdev_t *)netdev, ip_addr, true);
    if(idx < 0)
        return idx;
    
    /* 邻居项有效 */
valid:
    if(_arp_table[idx].state < ARP_STATE_NUD_STALE){
        if( _arp_table[idx].state == ARP_STATE_NUD_NONE ){
            arp_request_dst(_arp_table[idx].netdev, _arp_table[idx].ip_addr, NULL);
            arp_state_update_change_notify(idx, NULL, ARP_STATE_NUD_INCOMPLETE);
        }
        return idx;
    }

    if( _arp_table[idx].state == ARP_STATE_NUD_STALE || 
        _arp_table[idx].state == ARP_STATE_NUD_REACHABLE){
        /* 更新延迟探测时间 */
        _arp_table[idx].delay_probe_time_cd = EHIP_ARP_DELAY_PROBE_TIME;
    }
    return idx;
}


int arp_update_reachability(const ehip_netdev_t *netdev, const ipv4_addr_t ip_addr, int old_idx_or_minus){
    int idx;
    if(old_idx_or_minus >= 0 && old_idx_or_minus < (int)EHIP_ARP_CACHE_MAX_NUM && 
        _arp_table[old_idx_or_minus].ip_addr == ip_addr && _arp_table[old_idx_or_minus].netdev == netdev && 
        _arp_table[old_idx_or_minus].state != ARP_STATE_NUD_NONE){
        idx = old_idx_or_minus;
        goto valid;
    }
    idx = arp_find_entry((ehip_netdev_t *)netdev, ip_addr, false);
    if(idx < 0)
        return EH_RET_OK;
valid:
    if( _arp_table[idx].state < ARP_STATE_NUD_STALE )
        return EH_RET_AGAIN;
    arp_state_update_change_notify(idx, NULL, ARP_STATE_NUD_REACHABLE);
    return EH_RET_OK;
}

void arp_table_dump(void){
    const struct arp_entry* atp_entry;
    eh_infoln("############## arp table: ###############");
    for(int i = 0; i < (int)EHIP_ARP_CACHE_MAX_NUM; i++){
        atp_entry = _arp_table+i;
        if(atp_entry->state == ARP_STATE_NUD_FAILED) 
            continue;
        
        eh_infofl("ip: %03d.%03d.%03d.%03d mac: %.6hhq if: %s state: %-12s RC/DPT: %6d RT/ST: %6d", 
            ipv4_addr_to_dec0(atp_entry->ip_addr), ipv4_addr_to_dec1(atp_entry->ip_addr),
            ipv4_addr_to_dec2(atp_entry->ip_addr), ipv4_addr_to_dec3(atp_entry->ip_addr),
            &atp_entry->hw_addr, atp_entry->netdev->param->name, 
            atp_entry->state == ARP_STATE_NUD_NONE ?        "none"          :
            atp_entry->state == ARP_STATE_NUD_INCOMPLETE ?  "incomplete"    :
            atp_entry->state == ARP_STATE_NUD_STALE ?       "stale"         :
            atp_entry->state == ARP_STATE_NUD_REACHABLE ?   "reachable"     :
            atp_entry->state == ARP_STATE_NUD_DELAY ?       "delay"         : 
            atp_entry->state == ARP_STATE_NUD_PROBE ?       "probe"         : "unknown",
            atp_entry->delay_probe_time_cd, atp_entry->reachable_time_cd
        );
    }
}

static struct ehip_protocol_handle arp_protocol_handle = {
    .ptype = EHIP_PTYPE_ETHERNET_ARP,
    .handle = arp_handle,
    .node = EH_LIST_HEAD_INIT(arp_protocol_handle.node),
};


static int __init arp_protocol_parser_init(void){
    return ehip_protocol_handle_register(&arp_protocol_handle);
}

static void __exit arp_protocol_parser_exit(void){
    ehip_protocol_handle_unregister(&arp_protocol_handle);
}

static int __init arp_init(void){
    int ret;
    ret = eh_signal_register(&signal_arp_table_changed);
    if(ret < 0) return ret;

    eh_timer_advanced_init(eh_signal_to_custom_event(&signal_timer_1s), (eh_sclock_t)eh_msec_to_clock(1000*1), EH_TIMER_ATTR_AUTO_CIRCULATION);
    ret = eh_signal_register(&signal_timer_1s);
    if(ret < 0) goto signal_timer_1s_register_error;
    eh_signal_slot_connect(&signal_timer_1s, &slot_timer);
    eh_timer_start(eh_signal_to_custom_event(&signal_timer_1s));
    memset(&_arp_table, 0, sizeof(_arp_table));
    return 0;
signal_timer_1s_register_error:
    eh_signal_unregister(&signal_arp_table_changed);
    return ret;
}

static void __exit arp_exit(void){
    eh_timer_stop(eh_signal_to_custom_event(&signal_timer_1s));
    eh_signal_slot_disconnect(&slot_timer);
    eh_signal_unregister(&signal_timer_1s);
    eh_signal_unregister(&signal_arp_table_changed);
    /* 避免connect signal_arptable_changed的任务继续运行导致的问题 */
    eh_signal_clean(&signal_arp_table_changed);
}


ehip_preinit_module_export(arp_init, arp_exit);
ehip_protocol_module_export(arp_protocol_parser_init, arp_protocol_parser_exit);
