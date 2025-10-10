/**
 * @file tcp.c
 * @brief tcp  协议实现 rfc793
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-04-26
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <eh.h>
#include <eh_error.h>
#include <eh_types.h>
#include <eh_event.h>
#include <eh_timer.h>
#include <eh_platform.h>
#include <eh_ringbuf.h>
#include <eh_signal.h>
#include <eh_debug.h>
#include <eh_signal.h>
#include <eh_hashtbl.h>
#include <eh_mem.h>
#include <eh_swab.h>
#include <ehip_error.h>
#include <ehip_buffer.h>
#include <ehip_chksum.h>
#include <ehip_core.h>
#include <ehip_module.h>
#include <ehip_netdev_trait.h>
#include <ehip-ipv4/route.h>
#include <ehip-ipv4/ip.h>
#include <ehip-ipv4/tcp.h>
#include <ehip-ipv4/route_refresh.h>
#include <ehip-ipv4/_pseudo_header.h>
#include <ehip-ipv4/ip_message.h>
#include <ehip-ipv4/ip_tx.h>


#define TCP_MSS_MIN_SIZE                    536U
#define TCP_TIMEOUT_CONNECT_DOWNCNT         2 /* 500ms-1000ms 之间*/
#define TCP_TIMEOUT_CONNECT_RETRY           6
#define TCP_TIMEOUT_CONNECT_SIGNAL          ((eh_signal_base_t *)(&signal_ehip_timer_500ms))

#define TCP_TIMEOUT_RETRANSMIT_FIN_DOWNCNT  2
#define TCP_TIMEOUT_RETRANSMIT_FIN_RETRY    6
#define TCP_TIMEOUT_RETRANSMIT_FIN_SIGNAL   ((eh_signal_base_t *)(&signal_ehip_timer_500ms))

#define TCP_TIMEOUT_DELAY_ACK_DOWNCNT       1 /* 0ms-100ms之间 */
#define TCP_TIMEOUT_DELAY_ACK_RETRY         0
#define TCP_TIMEOUT_DELAY_ACK_SIGNAL         ((eh_signal_base_t *)(&signal_ehip_timer_100ms))

#define TCP_TIMEOUT_TIME_WAIT_DOWNCNT       120
#define TCP_TIMEOUT_TIME_WAIT_RETRY         0
#define TCP_TIMEOUT_TIME_WAIT_SIGNAL        ((eh_signal_base_t *)(&signal_ehip_timer_1s))

#define TCP_DELAY_ACK_TIMEOUT              200      /* 延迟ACK超时 x ms */
#define TCP_TX_SACK_MAX_SACK_CNT           3        /* sack最大就3个即可，超过该数会超出最大TCP头大小 */
#define TCP_QUICK_RTO                      50
#define TCP_INIT_RTO                       200
#define TCP_MAX_RTO                        (1000 * 60)
#define TCP_MIN_RTO                        (200)
#define TCP_LAN_MIN_RTO                    (8)
#define TCP_MAX_RTT                        (1000 * 30)
#define TCP_INIT_SSTHRESH                  8


#define TCP_PCB_PRIVATE_FLAGS_ANY                   0x00000001U
#define TCP_PCB_PRIVATE_FLAGS_AUTO_PORT             0x00000002U
#define TCP_PCB_PRIVATE_FLAGS_USER_CLOSED           0x00000004U
#define TCP_PCB_PRIVATE_FLAGS_BIT_WIDTH             16U


#define TCP_FRAGMENT_SEGMENT_MAX_NUM (((EHIP_TCP_FRAGMENT_SEGMENT_MAX_NUM-1) | (0x01U)) & (0xFFU))

enum TCP_STATE{
    TCP_STATE_CLOSED = 0,
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECEIVED,
    TCP_STATE_ESTABLISHED,
/* 主动关闭 */
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSING,
    TCP_STATE_TIME_WAIT,
/* 被动关闭 */
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_LAST_ACK,
    TCP_STATE_MAX
};


#define tcp_pcb_is_any(pcb)                     ((pcb)->config_flags & TCP_PCB_PRIVATE_FLAGS_ANY)
#define tcp_pcb_is_auto_port(pcb)               ((pcb)->config_flags & TCP_PCB_PRIVATE_FLAGS_AUTO_PORT)
#define tcp_pcb_is_user_closed(pcb)             ((pcb)->config_flags & TCP_PCB_PRIVATE_FLAGS_USER_CLOSED)
#define tcp_pcb_is_tx_channel_idle(pcb)         ((pcb)->snd_nxt == (pcb)->snd_una && (pcb)->user_req_transmit == 0)


static eh_hashtbl_t         tcp_hash_tbl;
static uint16_t             tcp_bind_port = 0x8000;
struct tcp_base_opt{
    void (*events_callback)(tcp_pcb_t pcb, enum tcp_event state);
};


struct tcp_fragment_info{
    uint16_t    frag_tab[TCP_FRAGMENT_SEGMENT_MAX_NUM];
    uint16_t    fin:1;
    uint16_t    _r:7;
    uint16_t    frag_tab_len:8;
    uint16_t    window_size;
};

struct tcp_pcb{
    void                            *userdata;
    int                             arp_idx_cache;
    ipv4_addr_t                     gw_addr;
    uint16_t                        config_flags;
    union{
        uint16_t                    flags;
        struct {
            uint16_t                dst_support_sack:1;         /* 对方是否支持 SACK */
            uint16_t                rx_win_full:1;              /* 接收窗口是否已满 */
            uint16_t                dup_ack_cnt:2;              /* 重复ACK计数器 */
            uint16_t                need_ack:1;                 /* 是否需要ACK */
            uint16_t                wait_minor_ack:1;           /* 是否正在等待小分组ACK */
            uint16_t                retransmit:1;               /* 是否正在重传 */
            uint16_t                sack_retransmit:1;          /* 是否正在SACK重传 */
            uint16_t                full_window_send:1;         /* 是否发送了一个完整的窗口 */
            uint16_t                later_transmit:1;           /* 是否需要延迟发送 */
            uint16_t                user_req_transmit:1;        /* 用户请求发送 */
            uint16_t                user_req_disconnect:1;      /* 用户请求断开 */
            uint16_t                fin_sent:1;                 /* 是否发送了FIN */
        };
    };
    struct eh_hashtbl_node          *node;
    struct tcp_base_opt             opt;
    uint32_t                        last_route_trait_value;
    uint32_t                        ts_recent;                  /* 最近的时间戳 */
    eh_signal_slot_t                slot_timer_timeout;
    eh_signal_slot_t                slot_timer_rto_timeout;
    EH_STRUCT_CUSTOM_SIGNAL(eh_event_timer_t) 
                                    signal_timer_rto;           /* 超时重传定时器 */
    eh_ringbuf_t*                   rx_buf;
    eh_ringbuf_t*                   tx_buf;
    uint16_t                        rx_buf_size;
    uint16_t                        tx_buf_size;
    uint32_t                        snd_nxt;                    /* 当前发送的 seq */
    uint32_t                        snd_una;                    /* 等待ACK的 seq */
    uint32_t                        snd_retry;                  /* 重传 seq */
    uint32_t                        snd_sml;                    /* 等待中的小分组 seq */
    uint32_t                        rcv_nxt;                    /* 回复对方的 ack 值,对方下一次通信应该使用的seq */
    uint16_t                        mss;
    enum route_table_type           route_type:8;
    enum TCP_STATE                  state:8;
    uint16_t                        rcv_wnd;                    /* 接收方(对方)窗口大小 单位字节 */
    uint16_t                        cwnd;                       /* 拥塞窗口大小 单位 mms */
    uint16_t                        ssthresh;                   /* 慢启动阈值 */
    uint16_t                        srtt;                       /* 平滑延迟 */
    uint16_t                        departure_time;             /* 发送时时间戳 */
    uint16_t                        mdev;                       /* 延迟方差 */
    uint16_t                        rto;                        /* 重传时间 */
    struct tcp_fragment_info        rx_fragment_info;
    uint8_t                         timeout_reload;
    uint8_t                         timeout_countdown;
    uint8_t                         retry_countdown;

};

struct tcp_server_base_opt{
    void (*new_connect)(tcp_pcb_t new_client);
};

struct tcp_server_pcb{
    struct eh_hashtbl_node          *node;
    struct tcp_server_base_opt      opt;
    uint16_t                        rx_buffer_size;
    uint16_t                        tx_buffer_size;
};


struct tcp_hash_key{
    uint16_be_t                     local_port;
    uint16_be_t                     remote_port;
    ipv4_addr_t                     local_addr;
    ipv4_addr_t                     remote_addr;
    ehip_netdev_t                   *netdev;
};

struct tcp_hash_value{
    void                            *pcb;
};

struct __packed  tcp_option_byte{
    uint8_t                          kind;
    uint8_t                          len;
    uint8_t                          data[0];
};


struct __packed  tcp_option_byte_syn{
    uint8_t                          kind_mss;
    uint8_t                          len_mss_4;
    uint16_be_t                      mss;
    uint8_t                          kind_nop_r0;
    uint8_t                          kind_nop_r1;
    uint8_t                          kind_sack_perm;
    uint8_t                          len_sack_perm_2;
    uint8_t                          kind_nop_r2;
    uint8_t                          kind_nop_r3;
    uint8_t                          kind_tsopt;
    uint8_t                          len_tsopt_10;
    uint32_be_t                      tsval;
    uint32_be_t                      tsecr;
};

struct __packed  tcp_option_byte_ack{
    uint8_t                          kind_nop_r0;
    uint8_t                          kind_nop_r1;
    uint8_t                          kind_tsopt;
    uint8_t                          len_tsopt_10;
    uint32_be_t                      tsval;
    uint32_be_t                      tsecr;
};

struct __packed tcp_option_tsopt{
    struct tcp_option_byte          type;
    uint32_be_t                     tsval;
    uint32_be_t                     tsecr;
};

struct __packed tcp_option_sack{
    struct tcp_option_byte          type;
    struct {
        uint32_be_t left;
        uint32_be_t right;
    }sack[0];
};

struct tcp_recv_pack_info{
    const struct tcp_hdr              *hdr;
    const struct tcp_option_sack      *opt_sack;
    const struct tcp_option_tsopt     *opt_tsopt;
    uint32_t                          ack_cnt;

#define TCP_RECV_DATA_RET_SUCCESS     0x00000001        /* 接收到数据 */
#define TCP_RECV_DATA_RET_FIN         0x00000002        /* 接收到FIN */
#define TCP_RECV_DATA_RET_PUSH        0x00000004        /* 意味着需要推送数据给用户 */
#define TCP_RECV_DATA_RET_ACK         0x00000008        /* 需要响应ACK */
    uint16_t                          recv_flags;
    ehip_buffer_size_t                data_len;
};

struct tcp_send_option_info{
    uint32_t            now_ms;
    ehip_buffer_size_t  option_len;
    uint8_t             sack_size;
    uint8_t             frag_len;
};

#define tcp_pcb_to_key(pcb)          (((struct tcp_hash_key*)eh_hashtbl_node_key((pcb)->node)))
#define tcp_pcb_to_netdev(pcb)        (((struct tcp_hash_key*)eh_hashtbl_node_key((pcb)->node))->netdev)

#define TCP_OPTION_KIND_EOL                  0
#define TCP_OPTION_KIND_NOP                  1
#define TCP_OPTION_KIND_MSS                  2
#define TCP_OPTION_KIND_WSOPT                3
#define TCP_OPTION_KIND_SACK_PERMITTED       4
#define TCP_OPTION_KIND_SACK                 5
#define TCP_OPTION_KIND_TSOPT                8
#define TCP_OPTION_KIND_TCP_MD5             19
#define TCP_OPTION_KIND_UTO                 28
#define TCP_OPTION_KIND_TCP_AO              29


typedef void (*tcp_state_recv_dispose)(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info);

static void tcp_closed_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info);
static void tcp_time_wait_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info);
static void tcp_listen_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info);
static void tcp_syn_sent_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info);
static void tcp_syn_recv_or_established_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info);
static void tcp_fin_wait_1_or_2_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info);
static void tcp_close_wait_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info);
static void tcp_closing_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info);
static void tcp_last_ack_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info);


static int tcp_transmit_ctrl(struct tcp_pcb *pcb, uint16_t flags, uint32_t seq);
static int tcp_connect(struct tcp_pcb *pcb, bool is_client);
static bool tcp_close(struct tcp_pcb *pcb, bool is_user_close);
static void tcp_interior_try_close(struct tcp_pcb *pcb, enum tcp_event close_state);
static int tcp_start_simple_timer(struct tcp_pcb *pcb, eh_signal_base_t *timer_signal_type, uint8_t timeout_countdown, uint8_t retry_countdown);
static void tcp_stop_simple_timer(struct tcp_pcb *pcb);
static int tcp_client_retry_send_internal(struct tcp_pcb *pcb, uint32_t send_seq, ehip_buffer_size_t send_size, bool is_sack_mode);
static void tcp_client_lose_fragment_retry_send(struct tcp_pcb *pcb, const struct tcp_option_sack *sack);
static void tcp_client_enter_retransmit(struct tcp_pcb *pcb);
static int tcp_client_data_send(struct tcp_pcb *pcb);
static void tcp_client_auto_send(struct tcp_pcb *pcb, const struct tcp_option_sack *sack);
static tcp_state_recv_dispose tcp_state_recv_dispose_tab[] = {
    [TCP_STATE_CLOSED] = tcp_closed_recv_dispose,
    [TCP_STATE_LISTEN] = tcp_listen_recv_dispose,
    [TCP_STATE_SYN_SENT] = tcp_syn_sent_recv_dispose,
    [TCP_STATE_SYN_RECEIVED] = tcp_syn_recv_or_established_recv_dispose,
    [TCP_STATE_ESTABLISHED] = tcp_syn_recv_or_established_recv_dispose,

    [TCP_STATE_FIN_WAIT_1] = tcp_fin_wait_1_or_2_recv_dispose,
    [TCP_STATE_FIN_WAIT_2] = tcp_fin_wait_1_or_2_recv_dispose,
    [TCP_STATE_CLOSING] = tcp_closing_recv_dispose,
    [TCP_STATE_TIME_WAIT] = tcp_time_wait_recv_dispose,

    [TCP_STATE_CLOSE_WAIT] = tcp_close_wait_recv_dispose,
    [TCP_STATE_LAST_ACK] = tcp_last_ack_recv_dispose,
};


static int tcp_transmit_syn(struct tcp_pcb *pcb, bool is_syn_ack, uint32_t seq);


static uint16_be_t tcp_bind_port_alloc(void){
    uint16_be_t port;
    if(!(tcp_bind_port & 0x8000))
        tcp_bind_port = 0x8000;
    port = eh_hton16(tcp_bind_port);
    tcp_bind_port++;
    return port;
}

static inline void tcp_client_events_callback(struct tcp_pcb *pcb, enum tcp_event state){
    if(pcb->opt.events_callback)
        pcb->opt.events_callback((tcp_pcb_t)pcb, state);
}

static inline bool tcp_pcb_hashtbl_is_install(struct eh_hashtbl_node *node){
    return eh_hashtbl_node_is_insert(node);
}

static int tcp_pcb_hashtbl_install(struct eh_hashtbl_node *node, bool is_auto_port){
    int ret;
    struct tcp_hash_key *key;
    if(eh_hashtbl_node_is_insert(node)){
        return 0;
    }
    key = (struct tcp_hash_key*)eh_hashtbl_node_key(node);
    if(is_auto_port){
        for( ; ; ){
            key->local_port = tcp_bind_port_alloc();
            ret = eh_hashtbl_find(tcp_hash_tbl, key, (eh_hashtbl_kv_len_t)sizeof(struct tcp_hash_key), NULL);
            if(ret == 0)
                continue;
            break;
        }
    }else{
        ret = eh_hashtbl_find(tcp_hash_tbl, key, (eh_hashtbl_kv_len_t)sizeof(struct tcp_hash_key), NULL);
        if(ret == 0)
            return EHIP_RET_SRC_PORT_BUSY;
    }

    eh_hashtbl_node_key_refresh(tcp_hash_tbl, node);
    ret = eh_hashtbl_insert(tcp_hash_tbl, node);
    return ret;
}

static void tcp_pcb_hashtbl_uninstall(struct eh_hashtbl_node *node){
    eh_hashtbl_remove(tcp_hash_tbl, node);
}

static inline ehip_buffer_size_t tcp_recv_data_len(ehip_buffer_t *tcp_msg, const struct tcp_hdr *hdr){
    return (ehip_buffer_size_t)ehip_buffer_get_payload_size(tcp_msg) - (ehip_buffer_size_t)tcp_hdr_size(hdr);
}

static void tcp_recv_pack_info_init(struct tcp_recv_pack_info *info, ehip_buffer_t *tcp_msg, const struct tcp_hdr *hdr){
    memset(info, 0, sizeof(*info));
    info->hdr = hdr;
    info->data_len = tcp_recv_data_len(tcp_msg, hdr);
}

static void slot_function_timer_timeout(eh_event_t *e, void *arg){
    (void) e;
    struct tcp_pcb *pcb = (struct tcp_pcb *)arg;
    pcb->timeout_countdown--;
    if(pcb->timeout_countdown != 0)
        return ;
    pcb->timeout_countdown = pcb->timeout_reload;

    pcb->retry_countdown--;
    if(pcb->retry_countdown == 0){
        /* 最终超时处理 */
        eh_signal_slot_disconnect(&pcb->slot_timer_timeout);
        /* 根据状态机来进行处理 */
        switch (pcb->state) {
            case TCP_STATE_SYN_SENT:
            case TCP_STATE_SYN_RECEIVED:
                eh_mdebugfl(TCP, "TCP SYN_SENT/TCP_STATE_SYN_RECEIVED timeout, close pcb %p", pcb);
                tcp_interior_try_close(pcb, TCP_CONNECT_TIMEOUT);
                break;
            case TCP_STATE_FIN_WAIT_1:
            case TCP_STATE_FIN_WAIT_2:
            case TCP_STATE_CLOSING:
            case TCP_STATE_LAST_ACK:
                eh_mdebugfl(TCP, "TCP LAST_ACK timeout, close pcb %p", pcb);
                tcp_interior_try_close(pcb, TCP_ERROR);
                break;
            case TCP_STATE_TIME_WAIT:
                pcb->state = TCP_STATE_CLOSED;
                tcp_close(pcb, false);
                break;
            case TCP_STATE_ESTABLISHED:
                if( pcb->need_ack == 0)
                    return ;
                tcp_transmit_ctrl(pcb, TCP_FLAG_ACK, pcb->snd_nxt);
                pcb->need_ack = 0;
            default:
                break;
        }
        return ;
    }


    /* 重试处理 */
    switch(pcb->state){
        case TCP_STATE_SYN_SENT:
            /* 重传 SYN */
            pcb->timeout_reload = pcb->timeout_countdown = pcb->timeout_reload * 2;
            tcp_transmit_syn(pcb, false, pcb->snd_una);
            break;
        case TCP_STATE_SYN_RECEIVED:
            /* 重传 SYN+ACK */
            pcb->timeout_reload = pcb->timeout_countdown = pcb->timeout_reload * 2;
            tcp_transmit_syn(pcb, true, pcb->snd_una);
            break;
        case TCP_STATE_FIN_WAIT_1:
        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:
            /*  重传 FIN */
            pcb->timeout_reload = pcb->timeout_countdown = pcb->timeout_reload * 2;
            tcp_transmit_ctrl(pcb, TCP_FLAG_FIN|TCP_FLAG_ACK, pcb->snd_una);
            break;
        default:
            tcp_stop_simple_timer(pcb);
            break;
    }
}

static void slot_function_timer_rto(eh_event_t *e, void *arg){
    (void)e;
    struct tcp_pcb *pcb = (struct tcp_pcb *)arg;
    int rto_tmp;
    if(pcb->snd_nxt == pcb->snd_una)
        return ;

    eh_mdebugfl(TCP_RTO_TIMEOUT, "snd_una:%u snd_nxt:%u rto:%u", pcb->snd_una, pcb->snd_nxt, pcb->rto);
    rto_tmp = pcb->rto;
    if(pcb->retransmit == 0){
        pcb->ssthresh = pcb->cwnd/2;
        if(pcb->ssthresh < 2)
            pcb->ssthresh = 2;
        pcb->cwnd = 1;
    }else{
        if(pcb->rto == TCP_MAX_RTO){
            /* 超时 */
            tcp_transmit_ctrl(pcb, TCP_FLAG_ACK|TCP_FLAG_RST, 0);
            tcp_interior_try_close(pcb, TCP_SEND_TIMEOUT);
            return ;
        }
    }

    rto_tmp = rto_tmp << 1;
    if( rto_tmp > TCP_MAX_RTO){
        pcb->rto = TCP_MAX_RTO;
    }else{
        pcb->rto = (uint16_t)rto_tmp;
    }

    tcp_client_enter_retransmit(pcb);
    tcp_client_data_send(pcb);
}

static int tcp_start_simple_timer(struct tcp_pcb *pcb, eh_signal_base_t *timer_signal_type, uint8_t timeout_countdown, uint8_t retry_countdown){
    int ret;
    ret = eh_signal_slot_connect(timer_signal_type, &pcb->slot_timer_timeout);
    if(ret < 0)
        return ret;
    pcb->retry_countdown = retry_countdown + 1;
    pcb->timeout_countdown = timeout_countdown;
    pcb->timeout_reload = timeout_countdown;
    return 0;
}


static void tcp_stop_simple_timer(struct tcp_pcb *pcb){
    eh_signal_slot_disconnect(&pcb->slot_timer_timeout);
}


static tcp_pcb_t tcp_pcb_base_new(uint16_t config_flags, struct tcp_hash_key *key, uint16_t rx_buf_size, uint16_t tx_buf_size){
    struct tcp_pcb *new_pcb;
    struct tcp_hash_value *node_value;
    struct tcp_hash_key *node_key;
    int ret;
    if(key->local_port == 0){
        config_flags |= TCP_PCB_PRIVATE_FLAGS_AUTO_PORT;
    }

    new_pcb = (struct tcp_pcb *)eh_malloc(sizeof(struct tcp_pcb));
    if(new_pcb == NULL)
        return eh_error_to_ptr(EH_RET_MALLOC_ERROR);
    memset(new_pcb, 0, sizeof(struct tcp_pcb));
    new_pcb->arp_idx_cache = -1;
    new_pcb->config_flags = config_flags;
    new_pcb->node = eh_hashtbl_node_new(
        (eh_hashtbl_kv_len_t)sizeof(struct tcp_hash_key), 
        (eh_hashtbl_kv_len_t)sizeof(struct tcp_hash_value));
    if(new_pcb->node == NULL){
        ret = EH_RET_MALLOC_ERROR;
        goto eh_hashtbl_node_new_error;
    }
    node_value = eh_hashtbl_node_value(new_pcb->node);
    node_key = eh_hashtbl_node_key(new_pcb->node);
    node_value->pcb = (tcp_pcb_t)new_pcb;
    memcpy(node_key, key, sizeof(struct tcp_hash_key));

    new_pcb->rx_buf_size = rx_buf_size;
    new_pcb->tx_buf_size = tx_buf_size;
    new_pcb->rx_buf = NULL;
    new_pcb->tx_buf = NULL;
    eh_signal_slot_init(&new_pcb->slot_timer_timeout, slot_function_timer_timeout, new_pcb);
    eh_signal_slot_init(&new_pcb->slot_timer_rto_timeout, slot_function_timer_rto, new_pcb);

    
    eh_signal_init(&new_pcb->signal_timer_rto);
    eh_timer_advanced_init(
       eh_signal_to_custom_event(&new_pcb->signal_timer_rto), 
            0, 0);
    ret = eh_signal_register(&new_pcb->signal_timer_rto);
    if(ret < 0){
        goto eh_signal_register_timer_delay_ack_error;
    }
    eh_signal_slot_connect(&new_pcb->signal_timer_rto, &new_pcb->slot_timer_rto_timeout);

    return (tcp_pcb_t)new_pcb;
eh_signal_register_timer_delay_ack_error:
    eh_hashtbl_node_delete(NULL, new_pcb->node);
eh_hashtbl_node_new_error:
    eh_free(new_pcb);
    return eh_error_to_ptr(ret);
}


static int tcp_route_refresh(struct tcp_pcb *pcb){
    struct tcp_hash_key *key;
    enum route_table_type route_type = ROUTE_TABLE_UNKNOWN;
    int ret;
    uint32_t route_refresh_flags = ROUTE_REFRESH_FLAGS_ALLOW_UNICAST | 
        ROUTE_REFRESH_FLAGS_ALLOW_LOOPBACK | ROUTE_REFRESH_FLAGS_CHECKED_SRC_ADDR;
    if(tcp_pcb_is_any(pcb))
        route_refresh_flags |= ROUTE_REFRESH_FLAGS_REFRESH_SRC_ADDR;

    key = (struct tcp_hash_key*)eh_hashtbl_node_key(pcb->node);
    ret = ehip_route_refresh(&key->netdev, &key->local_addr, key->remote_addr, 
            &pcb->gw_addr, &route_type, &pcb->last_route_trait_value, route_refresh_flags);
    /* 无论是什么返回值都必须把route_type更新到pcb中 */
    pcb->route_type = (uint8_t)route_type;
    if(ret < 0)
        return ret;

    return 0;
}


static inline int tcp_tx_new(struct tcp_pcb *pcb, struct ip_message **ip_msg, ehip_buffer_t** out_buffer, ehip_buffer_size_t *out_buffer_size){
    struct ip_message *new_ip_msg;
    struct tcp_hash_key *key = tcp_pcb_to_key(pcb);
    ehip_buffer_t *out_buffer_p;
    ehip_buffer_size_t out_buffer_size_p;
    int ret;
    new_ip_msg = ip_message_tx_new(tcp_pcb_to_netdev(pcb), ipv4_make_tos(0, 0), 
        EHIP_IP_DEFAULT_TTL, IP_PROTO_TCP, key->local_addr, key->remote_addr, NULL, 0, 0, pcb->route_type);
    if(eh_ptr_to_error(new_ip_msg) < 0)
        return eh_ptr_to_error(new_ip_msg);
    ret = ip_message_tx_add_buffer(new_ip_msg, &out_buffer_p, &out_buffer_size_p);
    if(ret < 0){
        ip_message_free(new_ip_msg);
        return ret;
    }
    *ip_msg = new_ip_msg;
    *out_buffer = out_buffer_p;
    *out_buffer_size = out_buffer_size_p;
    return EH_RET_OK;
}


static void tcp_hdr_fill_checksum(struct tcp_pcb *pcb, struct tcp_hdr *hdr, uint8_t option_len, uint16_t payload_size){
    struct pseudo_header pseudo_hdr;
    uint16_t checksum = 0;

    pseudo_hdr.src_addr = tcp_pcb_to_key(pcb)->local_addr;
    pseudo_hdr.dst_addr = tcp_pcb_to_key(pcb)->remote_addr;
    pseudo_hdr.zero = 0;
    pseudo_hdr.proto = IP_PROTO_TCP;
    pseudo_hdr.len = eh_hton16(sizeof(struct tcp_hdr) + option_len + payload_size);
    checksum = ehip_inet_chksum_accumulated(checksum, &pseudo_hdr, sizeof(struct pseudo_header));
    checksum = ehip_inet_chksum_accumulated(checksum, hdr, (int)sizeof(struct tcp_hdr) + option_len + payload_size);
    hdr->check = checksum;
}

static void tcp_hdr_fill(struct tcp_pcb *pcb, struct tcp_hdr *hdr, uint8_t option_len,  uint16_t hdr_flags, uint32_t seq, uint32_t ack_seq){
    hdr->source = tcp_pcb_to_key(pcb)->local_port;
    hdr->dest = tcp_pcb_to_key(pcb)->remote_port;
    hdr->seq = eh_hton32(seq);
    hdr->ack_seq = hdr_flags & TCP_FLAG_ACK ? eh_hton32(ack_seq) : 0;
    hdr->flags = 0;
    hdr->flags |= hdr_flags;
    hdr->doff = ((unsigned int)(eh_align_up(option_len, 4) >> 2) + (unsigned int)(sizeof(struct tcp_hdr) >> 2)) & 0x0F;
    hdr->window = pcb->rx_buf ? eh_hton16((uint16_t)eh_ringbuf_free_size(pcb->rx_buf)) : 0;
    hdr->check = 0;
    hdr->urg_ptr = 0;
}

static void tcp_option_info_get(struct tcp_pcb *pcb, struct tcp_send_option_info *info){
    info->now_ms = (uint32_t)eh_clock_to_msec(eh_get_clock_monotonic_time());
    info->option_len = (ehip_buffer_size_t)sizeof(struct tcp_option_byte_ack);
    if(pcb->rx_fragment_info.frag_tab_len >= 2 && pcb->dst_support_sack){
        info->frag_len = (uint8_t)((pcb->rx_fragment_info.frag_tab_len)/2);
        info->frag_len = info->frag_len > TCP_TX_SACK_MAX_SACK_CNT ? TCP_TX_SACK_MAX_SACK_CNT : info->frag_len;
        info->sack_size = (uint8_t)(2 + (info->frag_len * 2 * sizeof(uint32_t))); /*  kind-sack + 1_start + 1_end +...+ */
        info->option_len += (ehip_buffer_size_t)(2 + info->sack_size); /* 2byte padding + sack */
    }else{
        info->frag_len = 0;
        info->sack_size = 0;
    }
}

static void tcp_tx_send_option_fill(struct tcp_pcb *pcb, const struct tcp_send_option_info *info, struct tcp_hdr* tcp_hdr){
    struct tcp_option_byte_ack *tcp_option_byte_ack;
    tcp_option_byte_ack = (struct tcp_option_byte_ack *)tcp_hdr->options;
    tcp_option_byte_ack->kind_nop_r0 = TCP_OPTION_KIND_NOP;
    tcp_option_byte_ack->kind_nop_r1 = TCP_OPTION_KIND_NOP;
    tcp_option_byte_ack->kind_tsopt = TCP_OPTION_KIND_TSOPT;
    tcp_option_byte_ack->len_tsopt_10 = 10;
    tcp_option_byte_ack->tsval = eh_hton32(info->now_ms);
    tcp_option_byte_ack->tsecr = eh_hton32(pcb->ts_recent);

    if(info->frag_len){
        uint8_t *sack_option_2_byte_pad  = (uint8_t *)(tcp_option_byte_ack + 1);
        struct tcp_option_byte *tcp_option_byte_sack = (struct tcp_option_byte *)(sack_option_2_byte_pad + 2);
        struct{
            uint32_be_t left;
            uint32_be_t right;
        }* sack_option_2_byte_pad_sack = (void*)tcp_option_byte_sack->data;
        uint32_t left, right;
        int w = 0;
        
        sack_option_2_byte_pad[0] = TCP_OPTION_KIND_NOP;
        sack_option_2_byte_pad[1] = TCP_OPTION_KIND_NOP;
        tcp_option_byte_sack->kind = TCP_OPTION_KIND_SACK;
        tcp_option_byte_sack->len = info->sack_size;

        left = pcb->rcv_nxt + pcb->rx_fragment_info.frag_tab[0];
        right = left + pcb->rx_fragment_info.frag_tab[1];
        do{
            sack_option_2_byte_pad_sack[w].left = eh_hton32(left);
            sack_option_2_byte_pad_sack[w].right = eh_hton32(right);
            w++;
            if(w >= info->frag_len)
                break;
            left = right + pcb->rx_fragment_info.frag_tab[2*w];
            right = left + pcb->rx_fragment_info.frag_tab[2*w+1];
        }while(1);
    }
}

static int tcp_transmit_ctrl(struct tcp_pcb *pcb, uint16_t flags, uint32_t seq){
    struct tcp_hdr *tcp_hdr;
    struct ip_message *ip_msg = NULL;
    ehip_buffer_t *buffer = NULL;
    ehip_buffer_size_t buffer_size = 0;
    ehip_netdev_t *netdev = tcp_pcb_to_netdev(pcb);
    struct tcp_send_option_info option_info;
    int ret;
    
    // eh_mdebugfl(TCP_TX_CTRL, "s:%u a:%u", seq, pcb->rcv_nxt);
    ret = tcp_tx_new(pcb, &ip_msg, &buffer, &buffer_size);
    if(ret < 0)
        return ret;
    tcp_option_info_get(pcb, &option_info);
    tcp_hdr = (struct tcp_hdr*)ehip_buffer_payload_append(buffer, (ehip_buffer_size_t)(sizeof(struct tcp_hdr) + option_info.option_len));
    tcp_tx_send_option_fill(pcb, &option_info, tcp_hdr);
    tcp_hdr_fill(pcb, tcp_hdr, (uint8_t)option_info.option_len, flags, seq, pcb->rcv_nxt);
    tcp_hdr_fill_checksum(pcb, tcp_hdr, (uint8_t)option_info.option_len, 0);
    ret = ip_message_tx_ready(ip_msg, NULL);
    if(ret < 0)
        goto ip_message_tx_ready_error;
    return ip_tx(netdev, ip_msg, &pcb->arp_idx_cache, pcb->gw_addr);
ip_message_tx_ready_error:
    ip_message_free(ip_msg);
    return ret;
}


static int tcp_transmit_msg(struct tcp_pcb *pcb, const struct tcp_send_option_info *info, uint16_t flags, uint32_t seq, ehip_buffer_size_t payload_size){
    struct tcp_hdr *tcp_hdr;
    struct ip_message *ip_msg = NULL;
    ehip_buffer_t *buffer = NULL;
    ehip_buffer_size_t buffer_size = 0;
    ehip_netdev_t *netdev = tcp_pcb_to_netdev(pcb);
    void *payload_data;
    int ret;

    ret = tcp_tx_new(pcb, &ip_msg, &buffer, &buffer_size);
    if(ret < 0)
        return ret;

    tcp_hdr = (struct tcp_hdr*)ehip_buffer_payload_append(buffer, (ehip_buffer_size_t)(sizeof(struct tcp_hdr) + info->option_len + payload_size));
    tcp_tx_send_option_fill(pcb, info, tcp_hdr);
    payload_data = ((uint8_t*)tcp_hdr->options) + info->option_len;
    eh_ringbuf_peek_copy(pcb->tx_buf, (ehip_buffer_size_t)(seq - pcb->snd_una), payload_data, payload_size);
    tcp_hdr_fill(pcb, tcp_hdr, (uint8_t)info->option_len, flags, seq, pcb->rcv_nxt);
    tcp_hdr_fill_checksum(pcb, tcp_hdr, (uint8_t)info->option_len, payload_size);
    ret = ip_message_tx_ready(ip_msg, NULL);
    if(ret < 0)
        goto ip_message_tx_ready_error;
    pcb->departure_time = (uint16_t)info->now_ms;
    ip_tx(netdev, ip_msg, &pcb->arp_idx_cache, pcb->gw_addr);
    return payload_size;
ip_message_tx_ready_error:
    ip_message_free(ip_msg);
    return ret;
}

static int tcp_transmit_syn(struct tcp_pcb *pcb, bool is_syn_ack, uint32_t seq){
    struct tcp_hdr *tcp_hdr;
    struct ip_message *ip_msg = NULL;
    ehip_buffer_t *buffer;
    ehip_buffer_size_t buffer_size = 0;
    ehip_netdev_t *netdev = tcp_pcb_to_netdev(pcb);
    int ret;
    struct tcp_option_byte_syn *tcp_option_byte_syn;
    uint32_t now_ms;

    ret = tcp_tx_new(pcb, &ip_msg, &buffer, &buffer_size);
    if(ret < 0)
        return ret;

    if(buffer_size < (ehip_buffer_size_t)(sizeof(struct tcp_hdr) + sizeof(struct tcp_option_byte_syn))){
        ret = EH_RET_INVALID_STATE;
        goto buffer_size_too_small;
    }
    tcp_hdr = (struct tcp_hdr*)ehip_buffer_payload_append(buffer, sizeof(struct tcp_hdr) + sizeof(struct tcp_option_byte_syn));
    tcp_option_byte_syn = (struct tcp_option_byte_syn *)tcp_hdr->options;

    /* 告知对方我的MSS */
    tcp_option_byte_syn->kind_mss =  TCP_OPTION_KIND_MSS;
    tcp_option_byte_syn->len_mss_4 = 4;
    tcp_option_byte_syn->mss = pcb->mss;

    /* 告知对方我支持 SACK */
    tcp_option_byte_syn->kind_nop_r0 = TCP_OPTION_KIND_NOP;
    tcp_option_byte_syn->kind_nop_r1 = TCP_OPTION_KIND_NOP;
    tcp_option_byte_syn->kind_sack_perm = TCP_OPTION_KIND_SACK_PERMITTED;
    tcp_option_byte_syn->len_sack_perm_2 = 2;

    /* 告知对方 TIMESTAMP */
    tcp_option_byte_syn->kind_nop_r2 = TCP_OPTION_KIND_NOP;
    tcp_option_byte_syn->kind_nop_r3 = TCP_OPTION_KIND_NOP;
    tcp_option_byte_syn->kind_tsopt = TCP_OPTION_KIND_TSOPT;
    tcp_option_byte_syn->len_tsopt_10 = 10;
    now_ms = (uint32_t)eh_clock_to_msec(eh_get_clock_monotonic_time());
    tcp_option_byte_syn->tsval = eh_hton32(now_ms);
    pcb->departure_time = (uint16_t)now_ms;
    
    tcp_option_byte_syn->tsecr = 0;

    tcp_hdr_fill(pcb, tcp_hdr, sizeof(struct tcp_option_byte_syn), TCP_FLAG_SYN | (is_syn_ack ? TCP_FLAG_ACK : 0), seq, pcb->rcv_nxt);
    tcp_hdr_fill_checksum(pcb, tcp_hdr, sizeof(struct tcp_option_byte_syn), 0);
    ret = ip_message_tx_ready(ip_msg, NULL);
    if(ret < 0)
        goto ip_message_tx_ready_error;
    ip_tx(netdev, ip_msg, &pcb->arp_idx_cache, pcb->gw_addr);
    return 0;
ip_message_tx_ready_error:
buffer_size_too_small:
    ip_message_free(ip_msg);
    return ret;
}

static int tcp_option_byte_parse(struct tcp_pcb *pcb, struct tcp_recv_pack_info *pack_info){
    uint8_t *option_ptr = (uint8_t *)pack_info->hdr->options;
    int option_len = tcp_hdr_options_size(pack_info->hdr);
    uint8_t *option_end = option_ptr + option_len;
    int ret = 0;
    struct tcp_option_byte *option_byte;
    while(option_ptr < option_end){
        option_byte = (struct tcp_option_byte *)option_ptr;
        switch (option_byte->kind) {
            case TCP_OPTION_KIND_EOL:
                goto quit;
            case TCP_OPTION_KIND_NOP:
                option_ptr++;
                continue;
            case TCP_OPTION_KIND_MSS:{
                if(option_byte->len != 4 || option_ptr + option_byte->len > option_end){
                    ret = EH_RET_INVALID_STATE;
                    goto quit;
                }
                if(pack_info->hdr->syn == 1){
                    uint16_t dts_mss;
                    dts_mss = eh_ntoh16(*(uint16_be_t *)(option_byte->data));
                    pcb->mss = pcb->mss > dts_mss ? dts_mss : pcb->mss;
                    eh_mdebugfl(TCP_INPUT, "tcp dst mss %d", pcb->mss);
                }
                break;
            }
            case TCP_OPTION_KIND_WSOPT:{
                if(option_byte->len != 3 || option_ptr + option_byte->len > option_end){ 
                    ret = EH_RET_INVALID_STATE;
                    goto quit;
                }
                /* 我们不支持窗口缩放 */
                break;
            }
            case TCP_OPTION_KIND_SACK_PERMITTED:{
                if(option_byte->len != 2 || option_ptr + option_byte->len > option_end){
                    ret = EH_RET_INVALID_STATE;
                    goto quit;
                }
                if(pack_info->hdr->syn == 1){
                    pcb->dst_support_sack = 1;
                    eh_mdebugfl(TCP_INPUT, "tcp dst support sack permitted");
                }
                break;
            }
            case TCP_OPTION_KIND_SACK:{
                if(option_byte->len < 2 || option_ptr + option_byte->len > option_end){
                    ret = EH_RET_INVALID_STATE;
                    goto quit;
                }
                pack_info->opt_sack = (struct tcp_option_sack  *)option_byte;
                break;
            }
            case TCP_OPTION_KIND_TSOPT:{
                int diff;
                uint32_t pack_time;

                if(option_byte->len != 10 || option_ptr + option_byte->len > option_end){
                    ret = EH_RET_INVALID_STATE;
                    goto quit;
                }
                pack_info->opt_tsopt = (struct tcp_option_tsopt *)option_byte;
                
                /* 对比时间戳，丢弃过去的包 */
                pack_time = eh_ntoh32(pack_info->opt_tsopt->tsval);
                if(pack_info->hdr->syn == 1){
                    pcb->ts_recent = pack_time;
                    break;
                }
                
                diff = (int)(pack_time - pcb->ts_recent);
                if(diff < 0){
                    eh_mdebugfl(TCP, "Discard out-of-order data packets. %u > %u", pcb->ts_recent, pack_time);
                    ret = EH_RET_INVALID_STATE;
                    goto quit;
                }

                if(eh_ntoh32(pack_info->hdr->seq) == pcb->rcv_nxt){
                    pcb->ts_recent = pack_time;
                }
                break;
            }
            case TCP_OPTION_KIND_TCP_MD5:{
                if(option_byte->len != 18 || option_ptr + option_byte->len > option_end){
                    ret = EH_RET_INVALID_STATE;
                    goto quit;
                }
                /* 我们不支持 TCP MD5 */
                eh_mwarnfl(TCP_INPUT, "tcp dst support tcp md5, but we not support it");
                break;
            }
            case TCP_OPTION_KIND_UTO:{
                if(option_byte->len != 4 || option_ptr + option_byte->len > option_end){
                    ret = EH_RET_INVALID_STATE;
                    goto quit;
                }
                /* 我们不支持 UTO */
                eh_mwarnfl(TCP_INPUT, "tcp dst support uto, but we not support it");
                break;
            }
            case TCP_OPTION_KIND_TCP_AO:{
                if(option_ptr + option_byte->len > option_end){
                    ret = EH_RET_INVALID_STATE;
                    goto quit;
                }
                /* 我们不支持 TCP AO */
                eh_mwarnfl(TCP_INPUT, "tcp dst support tcp ao, but we not support it");
                break;
            }
            default:{
                if(option_ptr + option_byte->len > option_end){
                    ret = EH_RET_INVALID_STATE;
                    goto quit;
                }
                eh_mwarnfl(TCP_INPUT, "tcp dst unknown option kind %d", option_byte->kind);
                break;
            }
        }
        option_ptr += option_byte->len;
    }
quit:
    return ret;
}

/**
 * @brief                   检查test_seq是否在seq区间内
 * @param  start_seq        tcp头中的seq
 * @param  end_seq          seq加上数据长度
 * @param  test_seq         被测试的seq
 * @return bool             若test_seq在seq区间内返回 true 反之 false
 */
static __function_const bool tcp_seq_check(uint32_t start_seq, uint32_t end_seq, uint32_t test_seq){
    end_seq = end_seq - start_seq;
    test_seq = test_seq - start_seq;
    return test_seq < end_seq;
}


#define TCP_RECV_ACK_DUP                     0         /* 重复的ACK */
#define TCP_RECV_ACK_RET_FAST_RETRANSMIT    -1         /* 快速重传 */
#define TCP_RECV_ACK_RET_ON_RECV            -2         /* 没有收到ACK */
#define TCP_RECV_ACK_RET_OUT_OF_RANGE       -3         /* ACK不在范围内 */
static int tcp_recv_ack(struct tcp_pcb *pcb, struct tcp_recv_pack_info *pack_info){
    int ret;
    uint32_t ack_seq;
    if(pack_info->hdr->ack == 0 ) 
        return TCP_RECV_ACK_RET_ON_RECV;
        
    ack_seq = eh_ntoh32(pack_info->hdr->ack_seq);
    
    eh_mdebugfl(TCP, "ack_seq:%u snd_una:%u snd_nxt:%u", ack_seq, pcb->snd_una, pcb->snd_nxt);
    if(!tcp_seq_check(pcb->snd_una, pcb->snd_nxt + 1, ack_seq)){
        pcb->dup_ack_cnt =  0;
        return TCP_RECV_ACK_RET_OUT_OF_RANGE;
    }
    pcb->rcv_wnd = eh_ntoh16(pack_info->hdr->window);
    ret = (int)(ack_seq - pcb->snd_una);
    if(pack_info->data_len == 0){
        if(ret == 0){
            if(pcb->snd_nxt == pcb->snd_una){
                pcb->dup_ack_cnt = 0;
                return 0;
            }
            /* 重复ack计数，方便后面触发快速重传 */
            pcb->dup_ack_cnt++;
            if(pcb->dup_ack_cnt >= 3){
                /* 触发快速重传 */
                pcb->dup_ack_cnt = 0;
                return TCP_RECV_ACK_RET_FAST_RETRANSMIT;
            }
            return 0;
        }else{
            pcb->dup_ack_cnt = 0;
        }
    }
    pcb->snd_una = ack_seq;
    return ret;
}

static void tcp_update_srtt(struct tcp_pcb *pcb){
    uint16_t now = (uint16_t)eh_clock_to_msec(eh_get_clock_monotonic_time());
    uint16_t rtt = now - pcb->departure_time;
    int rto_tmp;
    if(rtt > TCP_MAX_RTT)
        return;
    if(rtt == 0)
        rtt = 1;

    if(pcb->srtt == 0){
        pcb->srtt = rtt;
        pcb->mdev = rtt >> 2;
    }else{
        // srtt = 7/8 srtt + 1/8 mrtt
        pcb->srtt -= (pcb->srtt >> 3);
        pcb->srtt += (rtt >> 3);
        // mdev = 3/4 mdev + 1/4 |srtt - mrtt|
        long var = (long)pcb->srtt - (long)rtt;
        pcb->mdev -= (pcb->mdev >> 2);
        if(var < 0) 
            var = -var;
        pcb->mdev += (uint16_t)(var >> 2);
    }
    rto_tmp = (uint16_t)(pcb->srtt + (pcb->mdev << 2));
    if(rto_tmp > TCP_MAX_RTO){
        pcb->rto = TCP_MAX_RTO;
    }else if(rto_tmp < TCP_MIN_RTO){
        pcb->rto = rto_tmp < TCP_LAN_MIN_RTO ? TCP_LAN_MIN_RTO : TCP_MIN_RTO;
    }else{
        pcb->rto = (uint16_t)rto_tmp;
    }


}


#define TCP_RECV_RST_RET_RECV      1   /* 接收到RST */
#define TCP_RECV_RST_RET_NO_RECV   0   /* 没有接收到RST */
#define TCP_RECV_RST_RET_DROP     -1   /* 应该丢弃 */
#define TCP_RECV_RST_RET_ACK      -2   /* 回复ACK */
static int tcp_recv_rst(struct tcp_pcb *pcb, struct tcp_recv_pack_info *pack_info){
    uint32_t seq;
    uint32_t win_limit;
    if(pack_info->hdr->rst == 0)
        return TCP_RECV_RST_RET_NO_RECV;
    seq = eh_ntoh32(pack_info->hdr->seq);
    if(pcb->rcv_nxt == seq){
        return TCP_RECV_RST_RET_RECV;
    }
    /* 如果有数据，那就直接丢弃该报文 */
    if(pack_info->data_len > 0)
        return TCP_RECV_RST_RET_DROP;
    /* 如果在窗口内，那么应该回一个ACK，否则也应该丢弃 */
    if(pcb->rx_buf)
        win_limit = pcb->rcv_nxt + (uint32_t)eh_ringbuf_free_size(pcb->rx_buf);
    else
        win_limit = pcb->rcv_nxt + pcb->rx_buf_size;

    if(tcp_seq_check(pcb->rcv_nxt, win_limit + 1, seq)){
        return TCP_RECV_RST_RET_ACK;
    }
    return TCP_RECV_RST_RET_DROP;
}


#define TCP_RECV_SYN_RET_NO_RECV   0   /* 没有接收到SYN */
#define TCP_RECV_SYN_RET_RST      -1   /* 回复RST */
#define TCP_RECV_SYN_RET_ACK      -2   /* 回复ACK */
static int tcp_recv_syn(struct tcp_pcb *pcb, struct tcp_recv_pack_info *pack_info){
    uint32_t seq;
    if(pack_info->hdr->syn == 0)
        return TCP_RECV_SYN_RET_NO_RECV;
    seq = eh_ntoh32(pack_info->hdr->seq);
    if(pcb->rcv_nxt == seq){
        pcb->rcv_nxt++;
        return TCP_RECV_SYN_RET_RST;
    }
    return TCP_RECV_SYN_RET_ACK;
}


/* 刷新rx分片信息的窗口大小或者结束符tag  */
static void tcp_refresh_rx_fragment_win_size(struct tcp_pcb *pcb, ehip_buffer_size_t new_windows_size){
    /* 接收大小超过旧的窗口大小，调整frag_tab的缓冲为新窗口 */
    uint16_t *tab_ptr = (uint16_t*)pcb->rx_fragment_info.frag_tab;
    ehip_buffer_size_t diff;
    diff = new_windows_size - pcb->rx_fragment_info.window_size;
    if(pcb->rx_fragment_info.fin)
        return ;
    if((pcb->rx_fragment_info.frag_tab_len)%2 == 0){
        tab_ptr[pcb->rx_fragment_info.frag_tab_len] = diff;
        pcb->rx_fragment_info.frag_tab_len++;
    }else{
        tab_ptr[pcb->rx_fragment_info.frag_tab_len-1] += diff;
    }
    pcb->rx_fragment_info.window_size = new_windows_size;
}

static uint32_t tcp_recv_data(struct tcp_pcb *pcb, ehip_buffer_size_t *data_len_ptr, const struct tcp_hdr *hdr){
    uint32_t data_start_seq;
    uint32_t data_end_seq;
    uint32_t rcv_nxt;       /* 期待对方这次发送的seq */
    uint32_t rx_win_limit;
    ehip_buffer_size_t data_len = *data_len_ptr;
    ehip_buffer_size_t rx_win_size;
    uint8_t *data_ptr;
    bool is_recv = false;
    bool win_fin = false;
    bool recv_fin = false;
    int start_diff;
    
    if(data_len == 0 && hdr->fin == false)
        return 0;
    // eh_mdebugfl(TCP_RECV_DATA, "s:%u a:%u", eh_ntoh32(hdr->seq), eh_ntoh32(hdr->ack_seq));
    data_start_seq = eh_ntoh32(hdr->seq);
    rcv_nxt = pcb->rcv_nxt;
    
    data_end_seq = data_start_seq + (uint32_t)data_len;
    if(data_end_seq == rcv_nxt){
        /* dup 数据*/
        if(hdr->fin){
            pcb->rcv_nxt++;
            return TCP_RECV_DATA_RET_FIN|TCP_RECV_DATA_RET_ACK;
        }
        return TCP_RECV_DATA_RET_ACK;
    }
    rx_win_size = (ehip_buffer_size_t)eh_ringbuf_free_size(pcb->rx_buf);
    rx_win_limit = rcv_nxt + (uint32_t)rx_win_size;
    if(rx_win_size == 0){
        /* 窗口为0 */
        if(hdr->fin){
            pcb->rcv_nxt++;
            return TCP_RECV_DATA_RET_PUSH|TCP_RECV_DATA_RET_FIN|TCP_RECV_DATA_RET_ACK;
        }
        return TCP_RECV_DATA_RET_PUSH|TCP_RECV_DATA_RET_ACK;
    }

    if(hdr->fin && data_end_seq == rx_win_limit){
        /* 这种情况比较特殊，刚好压在窗口上的FIN包 */
        win_fin = true;
    }
    data_ptr = ((uint8_t*)hdr) + (ehip_buffer_size_t)tcp_hdr_size(hdr);

    start_diff = (int)(rcv_nxt - data_start_seq);
    if(start_diff >= 0){
        if(start_diff < data_len){
            if((start_diff + rx_win_size) > data_len){
                /* 
                *                           |<--    rx_win_size   -->|
                *        |<--       data_len      -->|
                *        |<--  start_diff-->|
                *  |--------------------------------------------------------------| 
                *        ^                  ^        ^               ^
                *        |                  |        |               |  
                *        start_seq          |        end_seq         |  
                *        |                  |                        |  
                *        |                  next_dst_seq             rx_win_limit
                */
                data_ptr += start_diff;
                data_start_seq = rcv_nxt;
            }else{
                /*
                    *                          |<--rx_win_size -->|
                    *       |<--                  data_len             -->|
                    *       |<--  start_diff-->|  
                    *  |--------------------------------------------------------------| 
                    *       ^                  ^                  ^       ^      
                    *       |                  |                  |       |      
                    *       start_seq          |                  |       end_seq
                    *                          |                  |                              
                    *                          next_dst_seq       rx_win_limit
                    *
                    */
                data_ptr += start_diff;
                data_start_seq = rcv_nxt;
                data_end_seq = rx_win_limit;
            }
            is_recv = true;
        }
    }else{
        start_diff = -start_diff;
        if(start_diff < rx_win_size){
            if((start_diff + data_len) > rx_win_size){
                /* 
                *                           |<--      data_len    -->|
                *        |<--      rx_win_size    -->|
                *        |<--  start_diff-->|
                *  |--------------------------------------------------------------| 
                *        ^                  ^        ^               ^
                *        |                  |        |               |  
                *        next_dst_seq       |        rx_win_limit    |  
                *        |                  |                        |  
                *        |                  start_seq                end_seq
                */
                data_end_seq = rx_win_limit;
            }else{
                /* 
                *                           |<--  data_len -->|
                *        |<--              rx_win_size            -->|
                *        |<--  start_diff-->|
                *  |--------------------------------------------------------------| 
                *        ^                  ^                 ^      ^           
                *        |                  |                 |      |             
                *        next_dst_seq       |                 |      rx_win_limit  
                *        |                  |                 |  
                *        |                  start_seq         end_seq
                */
                
            }
            is_recv = true;
        }
    }


    /* 收到的数据与RX窗口重合 */
    if(is_recv){
        uint16_t rel_data_seq_start = (uint16_t)(data_start_seq - rcv_nxt);
        uint16_t rel_data_seq_end = (uint16_t)(data_end_seq - rcv_nxt);
        uint16_t rel_frag_tab[TCP_FRAGMENT_SEGMENT_MAX_NUM+3];
        uint16_t rel_segment_start = 0; 
        uint16_t rel_segment_end;
        uint16_t wl = 0;
        unsigned int rel_frag_write;
        uint16_t *rel_frag_tab_ptr;
        unsigned int i = 0;
        uint32_t ret_falgs;
        /* 提前减去rel_start_seq，方便后续rel_start_seq变化后直接与rel_start_seq进行运算 */
        data_ptr -= rel_data_seq_start;

        if(rel_data_seq_end > pcb->rx_fragment_info.window_size){
            tcp_refresh_rx_fragment_win_size(pcb, rx_win_size);
        }
        
        /*  #:为阳块 ，代表有数据，但是前面有空缺
         *  -:为阴块 , 代表后面有数据，但自身是空缺的
         *                  |-----------------|#################|---------------|#################|---------------|  
         *                  ^       ^                 ^                 ^               ^                 ^          
         *                  |       |                 |                 |               |                 |          
         *                  |       frag_tab[0]       frag_tab[1]       frag_tab[2]     frag_tab[3]       frag_tab[4]
         *                  (rcv_nxt)
         */
        rel_segment_end = pcb->rx_fragment_info.frag_tab[0];
        memset(rel_frag_tab, 0, sizeof(rel_frag_tab));
        rel_frag_write = 1;
        do{
            /* 需要分辨当前是阴块还是阳块，阴块需要补齐，i%2 == 0 则为阴块，若rel_start在阴块范围内，则需要补足 */
            if(i%2 == 0){
                /* 
                 * 补齐阴块 
                 * 判断 rel_data_seq_start 在不在这个区间中，若不在则直接处理下一块
                 */
                if(rel_data_seq_end < rel_segment_start || rel_data_seq_start >= rel_segment_end ){
                   rel_frag_tab[rel_frag_write++] = pcb->rx_fragment_info.frag_tab[i];
                   goto next;
                }
                if(rel_data_seq_end < rel_segment_end){
                    
                    if(rel_data_seq_start == rel_segment_start){
                        if(rel_data_seq_start != rel_data_seq_end){
                            /*  ||NEW-NEW-NEW|----------------| */
                            rel_frag_tab[rel_frag_write-1] += (uint16_t)(rel_data_seq_end - rel_data_seq_start);
                            eh_ringbuf_draft_write(pcb->rx_buf, rel_data_seq_start, data_ptr + rel_data_seq_start, rel_segment_end - rel_data_seq_start);
                        }else{
                            /*  |||---------------------------| */
                        }
                    }else if(rel_data_seq_start > rel_segment_start){
                        /*  |---------|NEW-NEW-NEW|-------| */
                        rel_frag_tab[rel_frag_write++] = rel_data_seq_start - rel_segment_start;
                        rel_frag_tab[rel_frag_write++] = rel_data_seq_end - rel_data_seq_start;
                        eh_ringbuf_draft_write(pcb->rx_buf, rel_data_seq_start, data_ptr + rel_data_seq_start, rel_data_seq_end - rel_data_seq_start);
                    }
                    rel_data_seq_start = rel_data_seq_end;
                    if(hdr->fin){
                        recv_fin = true;
                        break;
                    }
                    rel_frag_tab[rel_frag_write++] = rel_segment_end - rel_data_seq_end;
                }else{
                    if(rel_data_seq_start == rel_segment_start){
                        /*  ||NEW-NEW-NEW-NEW-NEW-NEW-NEW|| */
                        /* 与前一块合并，也得与后一块合并 */
                        rel_frag_tab[rel_frag_write-1] += pcb->rx_fragment_info.frag_tab[i];
                        rel_frag_write--;
                    }else{
                        /*  |----------------|NEW-NEW-NEW|| */
                        rel_frag_tab[rel_frag_write++] = rel_data_seq_start - rel_segment_start;
                        rel_frag_tab[rel_frag_write] = rel_segment_end - rel_data_seq_start;
                    }
                    eh_ringbuf_draft_write(pcb->rx_buf, rel_data_seq_start, data_ptr + rel_data_seq_start, rel_segment_end - rel_data_seq_start);
                    rel_data_seq_start = rel_segment_end;
                }
            }else{
                /* 处理阳块 */
                if(rel_frag_tab[rel_frag_write]){
                    rel_segment_start -= rel_frag_tab[rel_frag_write];
                }

                if(rel_data_seq_end < rel_segment_start || rel_data_seq_start >= rel_segment_end ){
                   rel_frag_tab[rel_frag_write++] = rel_segment_end - rel_segment_start;
                   goto next;
                }
                if(rel_data_seq_end < rel_segment_end){
                    if(hdr->fin){
                        /*  D代表要丢弃的数据，#代表要保留的数据 */
                        if(rel_data_seq_end != rel_segment_start){ 
                            /*  |#############|FIN|DDDDDDDDDDDDDD| */
                            rel_frag_tab[rel_frag_write++] = rel_data_seq_end-rel_segment_start;
                        }else{
                            /*  ||FIN|DDDDDDDDDDDDDDDDDDDDDDDDDDD| */
                        }
                        recv_fin = true;
                        break;
                    }
                    rel_frag_tab[rel_frag_write++] = rel_segment_end - rel_segment_start;
                    rel_data_seq_start = rel_data_seq_end;
                }else{
                    rel_frag_tab[rel_frag_write++] = rel_segment_end - rel_segment_start;
                    rel_data_seq_start = rel_segment_end;
                }
            }
        next:
            i++;
            if(i >= pcb->rx_fragment_info.frag_tab_len){
                if(rel_frag_tab[rel_frag_write])
                    rel_frag_write++;
                break;
            }

            rel_segment_start = rel_segment_end;
            rel_segment_end += pcb->rx_fragment_info.frag_tab[i];

        }while(1);

        wl = rel_frag_tab[0];
        rel_frag_write --;
        rel_frag_tab_ptr = &rel_frag_tab[1];
        if(rel_frag_write > 0 && rel_frag_tab_ptr[rel_frag_write - 1] == 0){
            /* 去掉最后一个空片段 */
            rel_frag_write--;
        }
        if(rel_frag_write > TCP_FRAGMENT_SEGMENT_MAX_NUM){
            /* 
             * rel_frag_tab_ptr: 
             *  |-----|#####|...  |#####|-----|#####|-----|
             *    OR
             *  |-----|#####|...  |#####|-----|###########|
             *  
             * rx_fragment_info.frag_tab:
             *  |-----|#####|...  |#####|-----|
             *                             |
             *                             ^ TCP_FRAGMENT_SEGMENT_MAX_NUM-1
             *  rel_frag_tab_ptr中多余的片段全部合并到 TCP_FRAGMENT_SEGMENT_MAX_NUM -2片段 中
             */
            unsigned int drop_start = TCP_FRAGMENT_SEGMENT_MAX_NUM - 1;
            uint16_t last_frag_len = 0;
            /* 分片表装不下了，丢弃后面的分片 */
            for(i = drop_start; i < rel_frag_write; i++){
                last_frag_len += rel_frag_tab_ptr[i];
            }
            rel_frag_tab_ptr[drop_start] = last_frag_len;
            rel_frag_write = TCP_FRAGMENT_SEGMENT_MAX_NUM;
            recv_fin = false;
            pcb->rx_fragment_info.fin = false;
        }
        memcpy(pcb->rx_fragment_info.frag_tab, rel_frag_tab_ptr, rel_frag_write * sizeof(uint16_t));
        ret_falgs = 0;
        pcb->rx_fragment_info.frag_tab_len = (uint8_t)rel_frag_write;
        if( !pcb->rx_fragment_info.fin )
            pcb->rx_fragment_info.fin = recv_fin;
        if(wl){
            uint16_t surplus_win_size = rx_win_size - wl;
            *data_len_ptr = wl;
            ret_falgs |= TCP_RECV_DATA_RET_SUCCESS;
            pcb->rx_fragment_info.window_size -= wl;
            eh_ringbuf_write_skip(pcb->rx_buf, wl);
            if(surplus_win_size == 0){
                pcb->rx_win_full = 1;
                ret_falgs |= TCP_RECV_DATA_RET_PUSH;
            }else if(hdr->psh || surplus_win_size < pcb->mss){
                ret_falgs |= TCP_RECV_DATA_RET_PUSH;
            }
            pcb->rcv_nxt += wl;
            if(pcb->rx_fragment_info.frag_tab_len > 1){
                /* 说明我们获得了旧分片，要进行立即回复 */
                ret_falgs |= TCP_RECV_DATA_RET_ACK;
            }
        }else{
            ret_falgs |= TCP_RECV_DATA_RET_ACK;
        }
        if(rel_frag_write == 0 && pcb->rx_fragment_info.fin){
            ret_falgs |= TCP_RECV_DATA_RET_FIN;
            pcb->rcv_nxt++;
        }

        return ret_falgs;
    }else if(win_fin){
        if(rx_win_size != pcb->rx_fragment_info.window_size){
            tcp_refresh_rx_fragment_win_size(pcb, rx_win_size);
        }
        pcb->rx_fragment_info.fin = 1;
        return TCP_RECV_DATA_RET_ACK;
    }
    return TCP_RECV_DATA_RET_ACK;
}

static void tcp_client_send_fin(struct tcp_pcb *pcb, enum TCP_STATE next_state){
    tcp_transmit_ctrl(pcb, TCP_FLAG_FIN|TCP_FLAG_ACK, pcb->snd_nxt);
    pcb->need_ack = 0;
    pcb->snd_nxt++;
    pcb->state = next_state;
    pcb->fin_sent = 1;
    /* 开定时器 重传FIN定时器 */
    tcp_stop_simple_timer(pcb);
    tcp_start_simple_timer(pcb, TCP_TIMEOUT_RETRANSMIT_FIN_SIGNAL, TCP_TIMEOUT_RETRANSMIT_FIN_DOWNCNT, TCP_TIMEOUT_RETRANSMIT_FIN_RETRY);
}


/* 丢失片段重发实现 */
static int tcp_client_retry_send_internal(struct tcp_pcb *pcb, uint32_t send_seq, ehip_buffer_size_t send_size, bool is_sack_mode){
    ehip_buffer_size_t pending_ack_size,window_size;
    ehip_buffer_size_t payload_size;
    ehip_buffer_size_t ready_payload;
    ehip_buffer_size_t ready_surplus_payload;
    ehip_buffer_size_t send_single_size;
    uint16_t  cwnd;
    int win_surplus;
    int ret = 0;
    struct tcp_send_option_info option_info;
    uint16_t last_flags = TCP_FLAG_ACK;

    pending_ack_size = (ehip_buffer_size_t)(send_seq - pcb->snd_una);
    cwnd = pcb->cwnd * pcb->mss;
    window_size = pcb->rcv_wnd > cwnd ? cwnd : pcb->rcv_wnd;

    /* 计算对方窗口剩余大小 */
    win_surplus = window_size - pending_ack_size;
    if(win_surplus <= 0){
        /* 窗口已满，不能进行数据发送 */
        return EH_RET_BUSY;
    }
    payload_size = (ehip_buffer_size_t)eh_ringbuf_size(pcb->tx_buf) - pending_ack_size;
    if(payload_size == 0)
        return EH_RET_AGAIN;

    tcp_option_info_get(pcb, &option_info);

    /* 计算单次最大发送的字节 */
    send_single_size = pcb->mss - option_info.option_len;

    send_size = win_surplus > send_size ? send_size : (ehip_buffer_size_t)win_surplus;

    if(payload_size > send_size){
        /* 计算本次最多能发送的字节 */
        if(is_sack_mode)
            ready_payload = send_size;
        else{
            if(send_size < send_single_size){
                ready_payload = (ehip_buffer_size_t)send_size;
            }else{
                ready_payload = (ehip_buffer_size_t)(send_size/send_single_size) * send_single_size;
            }
        }
    }else{
        last_flags |= TCP_FLAG_PSH;
        ready_payload = payload_size;
    }
    ready_surplus_payload = ready_payload;
    while(ready_surplus_payload){
        if(ready_surplus_payload > send_single_size){
            ret = tcp_transmit_msg(pcb, &option_info, TCP_FLAG_ACK, send_seq, send_single_size);
        }else{
            ret = tcp_transmit_msg(pcb, &option_info, last_flags, send_seq, ready_surplus_payload);
        }
        if(ret < 0)
            goto quit;
        ready_surplus_payload -= (ehip_buffer_size_t)ret;
        send_seq += (uint32_t)ret;
    }
quit:
    if(ready_surplus_payload != ready_payload)
        ret = ready_payload - ready_surplus_payload;
    return ret;
}

static void tcp_client_lose_fragment_retry_send(struct tcp_pcb *pcb, const struct tcp_option_sack *sack){
    uint32_t send_base;
    uint16_t snd_end;
    uint16_t frag_start = 0;
    int i, frag_end_tmp, ret = 0, frag_num = 0;
    bool is_try_send = false;
    uint8_t sack_idx[TCP_TX_SACK_MAX_SACK_CNT];

    if(pcb->snd_una == pcb->snd_nxt)
        return ;

    frag_num = (int)((sack->type.len - sizeof(*sack))/sizeof(sack->sack[0]));
    if(frag_num == 0)
        return ;

    for(i=0; i < TCP_TX_SACK_MAX_SACK_CNT; i++){
        sack_idx[i] = (uint8_t)i;
    }

    frag_num = frag_num > TCP_TX_SACK_MAX_SACK_CNT ? TCP_TX_SACK_MAX_SACK_CNT : frag_num;

    /* sort sack */
    if(frag_num > 1){
        for(i=0; i < frag_num - 1; i++){
            for(int j=i+1; j < frag_num; j++){
                if(eh_ntoh32(sack->sack[sack_idx[i]].left) > eh_ntoh32(sack->sack[sack_idx[j]].left)){
                    uint8_t tmp = sack_idx[i];
                    sack_idx[i] = sack_idx[j];
                    sack_idx[j] = tmp;
                }
            }
        }
    }

    if(pcb->sack_retransmit){
        send_base = pcb->snd_retry;
    }else{
        send_base = pcb->snd_una;
        pcb->snd_retry = send_base;
        pcb->full_window_send = 0;
        eh_mdebugfl(TCP_RETRY, "lose fragment retry: %u", pcb->snd_retry);
    }

    snd_end = (uint16_t)(pcb->snd_nxt - send_base);

    for(i=0; i < frag_num; i++){
        frag_end_tmp = (int)(eh_ntoh32(sack->sack[sack_idx[i]].left) - send_base);
        if(frag_end_tmp > (int)snd_end)
            break;
        if(frag_end_tmp > (int)frag_start){
            uint32_t frag_seq = frag_start + send_base;
            is_try_send = true;
            ret = tcp_client_retry_send_internal(pcb, frag_seq, (ehip_buffer_size_t)(frag_end_tmp - frag_start), true);
            if(ret <= 0)
                break;
            pcb->sack_retransmit = 1;
            pcb->need_ack = 0;
            pcb->snd_retry = frag_seq + (uint32_t)ret;
        }
        frag_start = (uint16_t)(eh_ntoh32(sack->sack[sack_idx[i]].right) - send_base);
        if(frag_start > snd_end)
            break;
    }
    if(is_try_send){
        eh_timer_config_interval(eh_signal_to_custom_event(&pcb->signal_timer_rto), eh_msec_to_clock(pcb->rto));
        eh_timer_restart(eh_signal_to_custom_event(&pcb->signal_timer_rto));
    }
}

static void tcp_client_enter_retransmit(struct tcp_pcb *pcb){
    pcb->retransmit = 1;
    pcb->sack_retransmit = 0;
    pcb->wait_minor_ack = 0;
    pcb->full_window_send = 0;
    pcb->snd_retry = pcb->snd_una;
}

static int tcp_client_data_send(struct tcp_pcb *pcb){
    ehip_buffer_size_t pending_ack_size,window_size;
    ehip_buffer_size_t payload_size;
    ehip_buffer_size_t ready_payload;
    ehip_buffer_size_t ready_surplus_payload;
    ehip_buffer_size_t send_single_size;
    ehip_buffer_size_t cwnd;
    ehip_buffer_size_t ring_buffer_size;
    int win_surplus;
    int ret = 0;
    struct tcp_send_option_info option_info;
    uint16_t last_flags = TCP_FLAG_ACK;
    uint32_t *snd_nxt;
    uint16_t  rto = pcb->rto;
    if(pcb->retransmit){
        snd_nxt = &pcb->snd_retry;
        /* 进行重发时，强行将buffer size设置在该范围内 */
        ring_buffer_size = (ehip_buffer_size_t)(pcb->snd_nxt - pcb->snd_una);
    }else{
        snd_nxt = &pcb->snd_nxt;
        ring_buffer_size = (ehip_buffer_size_t)eh_ringbuf_size(pcb->tx_buf);
    }

    pending_ack_size = (ehip_buffer_size_t)(*snd_nxt - pcb->snd_una);
    cwnd = pcb->cwnd * pcb->mss;
    window_size = pcb->rcv_wnd > cwnd ? cwnd : pcb->rcv_wnd;

    /* 计算对方窗口剩余大小 */
    win_surplus = window_size - pending_ack_size;
    if(win_surplus <= 0){
        /* 窗口已满，不能进行数据发送 */
        return EH_RET_BUSY;
    }
    payload_size = ring_buffer_size - pending_ack_size;
    if(payload_size == 0){
        pcb->user_req_transmit = 0;
        return 0;
    }
    
    tcp_option_info_get(pcb, &option_info);
    /* 计算单次最大发送的字节 */
    send_single_size = pcb->mss - option_info.option_len;

    if(payload_size > win_surplus){
        /* 计算本次最多能发送的字节 */
        if(win_surplus < send_single_size){
            ready_payload = (ehip_buffer_size_t)win_surplus;
        }else{
            ready_payload = (ehip_buffer_size_t)(win_surplus/send_single_size) * send_single_size;
        }
    }else{
        last_flags |= TCP_FLAG_PSH;
        ready_payload = payload_size;
    }

    ready_surplus_payload = ready_payload;
    while(ready_surplus_payload){
        if(ready_surplus_payload > send_single_size){
            ret = tcp_transmit_msg(pcb, &option_info, TCP_FLAG_ACK, *snd_nxt, send_single_size);
        }else if(ready_surplus_payload == send_single_size){
            ret = tcp_transmit_msg(pcb, &option_info, last_flags, *snd_nxt, ready_surplus_payload);
        }else if(pcb->wait_minor_ack == 0){
            /* 小包发送 */
            ret = tcp_transmit_msg(pcb, &option_info, last_flags, *snd_nxt, ready_surplus_payload);
            if(ret >= 0){
                /* 这个小包应该成功进行了发送 */
                pcb->wait_minor_ack = 1;
                pcb->snd_sml = *snd_nxt + (uint32_t)ret;
            }
        }else{
            goto quit;
        }
        if(ret < 0)
            goto quit;
        ready_surplus_payload -= (ehip_buffer_size_t)ret;
        *snd_nxt += (uint32_t)ret;
    }
quit:
    if(ready_surplus_payload != ready_payload){
        ret = ready_payload - ready_surplus_payload;
        if(payload_size == ret)
            pcb->user_req_transmit = 0; /* 发送完毕 */
        pcb->need_ack = 0;
        if((ehip_buffer_size_t)(ret + pcb->mss) > (cwnd-pending_ack_size)){
            /* 发送了一个完整的窗口 */
            pcb->full_window_send = 1;
            eh_mdebugfl(TCP_CWND, "tcp full window send.");
        }
    }
    eh_timer_config_interval(eh_signal_to_custom_event(&pcb->signal_timer_rto), eh_msec_to_clock(rto));
    eh_timer_restart(eh_signal_to_custom_event(&pcb->signal_timer_rto));
    return ret;

}

static void tcp_client_auto_send(struct tcp_pcb *pcb, const struct tcp_option_sack *sack){

    if(pcb->retransmit){
        tcp_client_data_send(pcb);
        return;
    }

    if(sack){
        tcp_client_lose_fragment_retry_send(pcb, sack);
    }

    if(!pcb->sack_retransmit && pcb->user_req_transmit){
        tcp_client_data_send(pcb);
    }

}


static void tcp_close_tx(struct tcp_pcb *pcb){
    if(pcb->tx_buf){
        eh_ringbuf_destroy(pcb->tx_buf);
        pcb->tx_buf = NULL;
    }
}

static void tcp_close_rx(struct tcp_pcb *pcb){
    if(pcb->rx_buf){
        eh_ringbuf_destroy(pcb->rx_buf);
        pcb->rx_buf = NULL;
    }
}

static int tcp_open_tx(struct tcp_pcb *pcb){
    eh_ringbuf_t* buf;
    if(pcb->tx_buf)
        return 0;
    buf = eh_ringbuf_create(pcb->tx_buf_size, NULL);
    if(eh_ptr_to_error(buf) < 0)
        return eh_ptr_to_error(buf);
    pcb->tx_buf = buf;
    return 0;
}

static int tcp_open_rx(struct tcp_pcb *pcb){
    eh_ringbuf_t* buf;
    if(pcb->rx_buf)
        return 0;
    buf = eh_ringbuf_create(pcb->rx_buf_size, NULL);
    if(eh_ptr_to_error(buf) < 0)
        return eh_ptr_to_error(buf);
    pcb->rx_buf = buf;
    return 0;
}



static bool tcp_close(struct tcp_pcb *pcb, bool is_user_close){
    struct tcp_hash_key* key;
    if(is_user_close){
        pcb->config_flags |= TCP_PCB_PRIVATE_FLAGS_USER_CLOSED;
        pcb->opt.events_callback = NULL;
        if(tcp_pcb_hashtbl_is_install(pcb->node))
            return false;
    }else{
        tcp_pcb_hashtbl_uninstall(pcb->node);
        if(!tcp_pcb_is_user_closed(pcb))
            return false;
    }
    
    key = (struct tcp_hash_key*)eh_hashtbl_node_key(pcb->node);
    eh_mdebugfl(TCP_CLOSE, IPV4_FORMATIO":%d <->"IPV4_FORMATIO":%d close....", 
            ipv4_formatio(key->local_addr), eh_ntoh16(key->local_port),
            ipv4_formatio(key->remote_addr), eh_ntoh16(key->remote_port));
    eh_signal_slot_disconnect(&pcb->slot_timer_timeout);
    eh_timer_stop(eh_signal_to_custom_event(&pcb->signal_timer_rto));

    eh_signal_slot_disconnect(&pcb->slot_timer_rto_timeout);
    eh_signal_unregister(&pcb->signal_timer_rto);
    tcp_close_tx(pcb);
    tcp_close_rx(pcb);
    eh_hashtbl_node_delete(NULL, pcb->node);
    eh_free(pcb);
    return true;
}

static void tcp_interior_try_close(struct tcp_pcb *pcb, enum tcp_event close_state){
    pcb->state = TCP_STATE_CLOSED;
    if(tcp_close(pcb, false) == false)
        tcp_client_events_callback(pcb, close_state);
}



#define TCP_COMMON_RECV_PRE_RET_QUIT            -1
#define TCP_COMMON_RECV_PRE_RET_DROP            -2
#define TCP_COMMON_RECV_PRE_RET_ACK_OF_RANGE    -3
static int tcp_common_recv_pre_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *pack_info){ 
    int ret;
    uint32_t snd_una_old;

    ret = tcp_recv_rst(pcb, pack_info);
    switch (ret) {
        case TCP_RECV_RST_RET_RECV:{
            /* 
            * 收到 RST
            * 迁移到 TCP_STATE_CLOSED
            */
            eh_mdebugfl(TCP_INPUT, "recv rst, migrate to TCP_STATE_CLOSED");
            tcp_interior_try_close(pcb, TCP_RECV_RST);
            return TCP_COMMON_RECV_PRE_RET_QUIT;
        }
        case TCP_RECV_RST_RET_DROP:
            return TCP_COMMON_RECV_PRE_RET_DROP;
        case TCP_RECV_RST_RET_ACK:
            tcp_transmit_ctrl(pcb, TCP_FLAG_ACK, pcb->snd_nxt);
            pcb->need_ack = 0;
            return TCP_COMMON_RECV_PRE_RET_QUIT;
        default:
            break;
    }

    ret = tcp_recv_syn(pcb, pack_info);
    switch (ret) {
        case TCP_RECV_SYN_RET_RST:{
            /* 
            * 发送 RST
            * 迁移到 TCP_STATE_CLOSED
            */
            tcp_transmit_ctrl(pcb, TCP_FLAG_ACK|TCP_FLAG_RST, 0);
            tcp_interior_try_close(pcb, TCP_DISCONNECTED);
            return TCP_COMMON_RECV_PRE_RET_QUIT;
        }
        case TCP_RECV_SYN_RET_ACK:{
            tcp_transmit_ctrl(pcb, TCP_FLAG_ACK, pcb->snd_nxt);
            pcb->need_ack = 0;
            return TCP_COMMON_RECV_PRE_RET_QUIT;
        }
        default:
            break;
    }
    
    ret = tcp_option_byte_parse(pcb, pack_info);
    if(ret < 0){
        return TCP_COMMON_RECV_PRE_RET_DROP;
    }

    snd_una_old = pcb->snd_una;    
    ret = tcp_recv_ack(pcb, pack_info);

    /* 开始计算平滑SRTT,应该实现一个函数来计算平滑SRTT,然后要处理进入快速重传后的拥塞避免处理 */
    if(pack_info->opt_tsopt){
        pcb->departure_time = (uint16_t)eh_ntoh32(pack_info->opt_tsopt->tsecr);
        tcp_update_srtt(pcb);
    }else if(pcb->retransmit == 0 && pcb->snd_nxt == pcb->snd_una){
        tcp_update_srtt(pcb);
    }

    switch (ret) {
        case TCP_RECV_ACK_DUP:
            return 0;
        case TCP_RECV_ACK_RET_FAST_RETRANSMIT:
            if(pcb->dst_support_sack || pcb->fin_sent){
                return 0;
            }

            if(pcb->retransmit){
                return TCP_COMMON_RECV_PRE_RET_QUIT;
            }

            /* 触发快速重传 */
            pcb->ssthresh =  pcb->cwnd / 2;
            if(pcb->ssthresh == 0)
                pcb->ssthresh = 1;
            pcb->cwnd = pcb->ssthresh;
            tcp_client_enter_retransmit(pcb);
            tcp_client_data_send(pcb);
            return TCP_COMMON_RECV_PRE_RET_QUIT;
        case TCP_RECV_ACK_RET_ON_RECV:
            return TCP_COMMON_RECV_PRE_RET_QUIT;
        case TCP_RECV_ACK_RET_OUT_OF_RANGE:
            return TCP_COMMON_RECV_PRE_RET_ACK_OF_RANGE;
    }



    if(pcb->wait_minor_ack && (int)(pcb->snd_sml - snd_una_old) <= ret){
        pcb->wait_minor_ack = 0;
    }

    if(pcb->sack_retransmit && (int)(pcb->snd_retry - snd_una_old) <= ret){
        pcb->sack_retransmit = 0;
    }

    if(pcb->retransmit && (int)(pcb->snd_nxt - snd_una_old) <= ret){
        /* 提前结束重传 */
        pcb->retransmit = 0;
    }
    
    if(pcb->full_window_send){
        bool full_window_send_succeed;
        if(pcb->retransmit){
            full_window_send_succeed = (int)(pcb->snd_retry - snd_una_old) <= ret;
        }else{
            full_window_send_succeed = (int)(pcb->snd_nxt - snd_una_old) <= ret;
        }
        if(full_window_send_succeed){
            pcb->full_window_send = 0;
            if(pcb->cwnd < pcb->ssthresh){
                /* 慢启动 */
                eh_mdebugfl(TCP_CWND, "slow start, cwnd:%u ssthresh:%u", pcb->cwnd, pcb->ssthresh);
                pcb->cwnd = (uint16_t)(pcb->cwnd << 1);
                if(pcb->cwnd > pcb->ssthresh)
                    pcb->cwnd = pcb->ssthresh;
            }else{
                /* 拥塞避免 */
                eh_mdebugfl(TCP_CWND, "congestion avoidance, cwnd:%u ssthresh:%u", pcb->cwnd, pcb->ssthresh);
                pcb->cwnd = (uint16_t)(pcb->cwnd + 1);
            }
        }
    }



    return ret;
}

static void tcp_common_recv_data_and_ack_pre_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info){

    recv_pack_info->recv_flags = (uint16_t)tcp_recv_data(pcb, &recv_pack_info->data_len, recv_pack_info->hdr);

    if((recv_pack_info->recv_flags & (TCP_RECV_DATA_RET_ACK | TCP_RECV_DATA_RET_PUSH | TCP_RECV_DATA_RET_FIN | TCP_RECV_DATA_RET_SUCCESS)))
        pcb->need_ack = 1;

    pcb->later_transmit = 1; /* 避免在回调函数中进行发送 */
    if(recv_pack_info->ack_cnt > 0){
        eh_ringbuf_read_skip(pcb->tx_buf, (int32_t)recv_pack_info->ack_cnt);
        /* 上一次数据接收到ACK */
        tcp_client_events_callback(pcb, TCP_RECV_ACK);
    }
    
    if( recv_pack_info->recv_flags & TCP_RECV_DATA_RET_PUSH || 
        (recv_pack_info->recv_flags & TCP_RECV_DATA_RET_FIN && eh_ringbuf_size(pcb->rx_buf))){
        /* 数据回调 */
        if(tcp_pcb_is_user_closed(pcb)){
            eh_ringbuf_clear(pcb->rx_buf);
        }else{
            tcp_client_events_callback(pcb, TCP_RECV_DATA);
        }
    }
    pcb->later_transmit = 0;
}


static void tcp_client_recv_data_auto_ack(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info){
    int ret;
    if(pcb->need_ack){
        if(recv_pack_info->recv_flags & (TCP_RECV_DATA_RET_ACK | TCP_RECV_DATA_RET_PUSH | TCP_RECV_DATA_RET_FIN) ){
            ret = tcp_transmit_ctrl(pcb, TCP_FLAG_ACK, pcb->snd_nxt);
            if(ret == 0){
                pcb->need_ack = 0;
            }else{
                eh_mwarnfl(TCP_INPUT, "tcp_transmit_ack_or_msg error %d", ret);
            }
        }else if(recv_pack_info->recv_flags & TCP_RECV_DATA_RET_SUCCESS && pcb->state == TCP_STATE_ESTABLISHED){
            /* 延迟ACK */
            tcp_start_simple_timer(pcb, TCP_TIMEOUT_DELAY_ACK_SIGNAL, TCP_TIMEOUT_DELAY_ACK_DOWNCNT, TCP_TIMEOUT_DELAY_ACK_RETRY);
        }
    }
}

static inline bool tcp_client_later_recv_is_fin(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info){
    const struct tcp_hdr *hdr;
    hdr = recv_pack_info->hdr;
    return recv_pack_info->hdr->fin && (eh_ntoh32(hdr->seq) + recv_pack_info->data_len) == (pcb->rcv_nxt - 1);
}

static void tcp_closed_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info){
    (void)pcb;
    (void)recv_pack_info;
    eh_mdebugfl(TCP_INPUT, "tcp closed state, ignore recv msg");
}

static void tcp_listen_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info){
    int ret;
    /* TCP 选项解析 */
    ret = tcp_option_byte_parse(pcb, recv_pack_info);
    if(ret < 0){
        eh_mwarnfl(TCP_INPUT, "tcp_option_byte_parse error %d", ret);
        goto drop;
    }

    pcb->rcv_nxt = eh_ntoh32(recv_pack_info->hdr->seq) + 1;

    ret = tcp_connect(pcb, false);
    if(ret < 0){
        eh_mwarnfl(TCP_INPUT, "tcp server tcp_connect error %d", ret);
        goto drop;
    }
    /* tcp_connect 会初始化一些变量，导致option变量被覆盖 */
    tcp_option_byte_parse(pcb, recv_pack_info);

    goto quit;
drop:
    tcp_interior_try_close(pcb, TCP_ERROR);
quit:
    return ;
}


static void tcp_syn_sent_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info){
    int ret;
    struct tcp_recv_pack_info pack_info;

    if( recv_pack_info->hdr->rst == 1){
        /* 
         * 收到 RST
         * 迁移到 TCP_STATE_CLOSED
         */
        eh_mdebugfl(TCP_INPUT, "tcp syn sent state, recv rst, migrate to TCP_STATE_CLOSED");
        pcb->state = TCP_STATE_CLOSED;
        tcp_pcb_hashtbl_uninstall(pcb->node);
        tcp_client_events_callback(pcb, TCP_RECV_RST);
        goto quit;
    }

    if( recv_pack_info->hdr->ack == 0 && recv_pack_info->hdr->syn == 0){
        goto drop;
    }

    memset(&pack_info, 0, sizeof(pack_info));
    recv_pack_info->hdr = recv_pack_info->hdr;

    if( recv_pack_info->hdr->ack == 0 && recv_pack_info->hdr->syn == 1){
        /* 
         * 判定为同时打开 
         * 发送 SYN + ACK 迁移到 TCP_STATE_SYN_RECEIVED
         */
        eh_mdebugfl(TCP_INPUT, "tcp syn sent state, recv syn without ack, migrate to TCP_STATE_SYN_RECEIVED");
        pcb->rcv_nxt = eh_ntoh32(recv_pack_info->hdr->seq) + 1;
        /* TCP 选项解析 */
        ret = tcp_option_byte_parse(pcb, &pack_info);
        if(ret < 0){
            eh_mwarnfl(TCP_INPUT, "tcp_option_byte_parse error %d", ret);
            goto drop;
        }
        ret = tcp_transmit_syn(pcb, true, pcb->snd_una);
        if(ret < 0){
            eh_mwarnfl(TCP_INPUT, "tcp_transmit_syn error %d", ret);
            goto drop;
        }
        pcb->snd_nxt = pcb->snd_una + 1;
        pcb->state = TCP_STATE_SYN_RECEIVED;
        goto quit;
    }

    if( recv_pack_info->hdr->ack == 1 && recv_pack_info->hdr->syn == 1){
        /* 
         * 收到 SYN + ACK
         * 迁移到 TCP_STATE_ESTABLISHED
         */
        if(recv_pack_info->hdr->ack_seq != eh_hton32(pcb->snd_una + 1))
            goto drop;
        /* TCP 选项解析 */
        ret = tcp_option_byte_parse(pcb, &pack_info);
        if(ret < 0){
            eh_mwarnfl(TCP_INPUT, "tcp_option_byte_parse error %d", ret);
            goto drop;
        }

        tcp_update_srtt(pcb);

        pcb->rcv_nxt = eh_ntoh32(recv_pack_info->hdr->seq) + 1;
        pcb->snd_una++;
        pcb->rcv_wnd = eh_ntoh16(recv_pack_info->hdr->window);
        
        /* 发ack */
        ret = tcp_transmit_ctrl(pcb, TCP_FLAG_ACK, pcb->snd_una);
        if(ret < 0){
            eh_mwarnfl(TCP_INPUT, "tcp_transmit_ack_or_msg error %d", ret);
            goto drop;
        }
        pcb->state = TCP_STATE_ESTABLISHED;
        tcp_stop_simple_timer(pcb);
        tcp_client_events_callback(pcb, TCP_CONNECTED);
        goto quit;
    }


drop:
quit:
    return ;
}

static void tcp_syn_recv_or_established_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info){
    int ret;
    ret = tcp_common_recv_pre_dispose(pcb, recv_pack_info);
    switch (ret) {
        case TCP_COMMON_RECV_PRE_RET_QUIT:
            goto quit;
        case TCP_COMMON_RECV_PRE_RET_DROP:
            goto drop;
        default:
            break;
    }

    if(ret > 0 && pcb->state == TCP_STATE_SYN_RECEIVED){
        ret--;
        pcb->state = TCP_STATE_ESTABLISHED;
        tcp_client_events_callback(pcb, TCP_CONNECTED);
    }

    recv_pack_info->ack_cnt = ret > 0 ? (uint32_t)ret : 0U;

    /* 处理数据接收和ACK接收 包括相关回调函数的调用*/
    tcp_common_recv_data_and_ack_pre_dispose(pcb, recv_pack_info);

    /* 数据自动发送 */
    tcp_client_auto_send(pcb, recv_pack_info->opt_sack);

    /* 通过接收数据情况自动ACK */
    tcp_client_recv_data_auto_ack(pcb, recv_pack_info);

    if(recv_pack_info->recv_flags & TCP_RECV_DATA_RET_FIN){
        /* 状态迁移 */
        pcb->state = TCP_STATE_CLOSE_WAIT;
        /* TCP_STATE_CLOSE_WAIT 状态下无需启动定时器 */
        tcp_stop_simple_timer(pcb);
        tcp_close_rx(pcb);
    
        /* 可通知客户端留一点遗言 */
        tcp_client_events_callback(pcb, TCP_RECV_FIN);
        /* 检查是否还有未发送的数据，若没有，则准备发送fin进入LAST ACK 状态 */
        if(tcp_pcb_is_tx_channel_idle(pcb)){
            eh_timer_stop(eh_signal_to_custom_event(&pcb->signal_timer_rto));
            tcp_close_tx(pcb);
            eh_mdebugfl(TCP_INPUT, "tcp syn recv or established state, snd_nxt == snd_una, migrate to TCP_STATE_LAST_ACK");
            tcp_client_send_fin(pcb, TCP_STATE_LAST_ACK);
        }
    }else if(pcb->user_req_disconnect && tcp_pcb_is_tx_channel_idle(pcb)){
        eh_timer_stop(eh_signal_to_custom_event(&pcb->signal_timer_rto));
        /* 用户请求断开连接 */
        tcp_close_tx(pcb);
        tcp_client_send_fin(pcb, TCP_STATE_FIN_WAIT_1);
    }

quit:
drop:
    return ;
}
static void tcp_fin_wait_1_or_2_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info){
    int ret;
    ret = tcp_common_recv_pre_dispose(pcb, recv_pack_info);
    switch (ret) {
        case TCP_COMMON_RECV_PRE_RET_QUIT:
            goto quit;
        case TCP_COMMON_RECV_PRE_RET_DROP:
            goto drop;
        default:
            break;
    }

    recv_pack_info->ack_cnt = 0U;

    /* 处理数据接收和ACK接收 包括相关回调函数的调用*/
    tcp_common_recv_data_and_ack_pre_dispose(pcb, recv_pack_info);
    
    /* 通过接收数据情况自动ACK */
    tcp_client_recv_data_auto_ack(pcb, recv_pack_info);

    if(pcb->state == TCP_STATE_FIN_WAIT_1){
        /* TCP_STATE_FIN_WAIT_1 */
        if(recv_pack_info->recv_flags & TCP_RECV_DATA_RET_FIN && ret > 0){
            /* 同时收到FIN和ACK ---> 进入 TCP_STATE_TIME_WAIT 状态  */
            pcb->state = TCP_STATE_TIME_WAIT;
            tcp_close_rx(pcb);
            tcp_stop_simple_timer(pcb);
            tcp_start_simple_timer(pcb, TCP_TIMEOUT_TIME_WAIT_SIGNAL, TCP_TIMEOUT_TIME_WAIT_DOWNCNT, TCP_TIMEOUT_TIME_WAIT_RETRY);
            tcp_client_events_callback(pcb, TCP_DISCONNECTED);
        }else if( recv_pack_info->recv_flags & TCP_RECV_DATA_RET_FIN ){
            /* 收到FIN ---> 进入 TCP_STATE_CLOSING 状态 */
            pcb->state = TCP_STATE_CLOSING;
            tcp_close_rx(pcb);
            tcp_stop_simple_timer(pcb);
            tcp_start_simple_timer(pcb, TCP_TIMEOUT_RETRANSMIT_FIN_SIGNAL, TCP_TIMEOUT_RETRANSMIT_FIN_DOWNCNT, TCP_TIMEOUT_RETRANSMIT_FIN_RETRY);
        }else if( ret > 0 ){
            /* 收到ACK ---> 进入 TCP_STATE_FIN_WAIT_2 状态 */
            pcb->state = TCP_STATE_FIN_WAIT_2;
            tcp_stop_simple_timer(pcb);
            tcp_start_simple_timer(pcb, TCP_TIMEOUT_TIME_WAIT_SIGNAL, TCP_TIMEOUT_TIME_WAIT_DOWNCNT, TCP_TIMEOUT_TIME_WAIT_RETRY);
        }
    }else{
        /* TCP_STATE_FIN_WAIT_2 */
        if(recv_pack_info->recv_flags & TCP_RECV_DATA_RET_FIN){
            /* 同时收到FIN ---> 进入 TCP_STATE_TIME_WAIT 状态  */
            pcb->state = TCP_STATE_TIME_WAIT;
            tcp_close_rx(pcb);
            tcp_stop_simple_timer(pcb);
            tcp_start_simple_timer(pcb, TCP_TIMEOUT_TIME_WAIT_SIGNAL, TCP_TIMEOUT_TIME_WAIT_DOWNCNT, TCP_TIMEOUT_TIME_WAIT_RETRY);
            tcp_client_events_callback(pcb, TCP_DISCONNECTED);
        }
    }

quit:
drop:
    return ;
}


static void tcp_closing_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info){
    int ret;
    
    ret = tcp_common_recv_pre_dispose(pcb, recv_pack_info);
    switch (ret) {
        case TCP_COMMON_RECV_PRE_RET_QUIT:
            goto quit;
        case TCP_COMMON_RECV_PRE_RET_DROP:
        case TCP_COMMON_RECV_PRE_RET_ACK_OF_RANGE:
            goto drop;
        default:
            break;
    }

    if(tcp_client_later_recv_is_fin(pcb, recv_pack_info))
        tcp_transmit_ctrl(pcb, TCP_FLAG_ACK, pcb->snd_nxt);
    if(ret > 0){
        /* 收到ACK ---> 进入 TCP_STATE_TIME_WAIT 状态  */
        pcb->state = TCP_STATE_TIME_WAIT;
        tcp_stop_simple_timer(pcb);
        tcp_start_simple_timer(pcb, TCP_TIMEOUT_TIME_WAIT_SIGNAL, TCP_TIMEOUT_TIME_WAIT_DOWNCNT, TCP_TIMEOUT_TIME_WAIT_RETRY);
        tcp_client_events_callback(pcb, TCP_DISCONNECTED);
    }
quit:
drop:
    return ;
}


static void tcp_time_wait_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info){
    int ret;
    ret = tcp_common_recv_pre_dispose(pcb, recv_pack_info);
    switch (ret) {
        case TCP_COMMON_RECV_PRE_RET_QUIT:
            goto quit;
        case TCP_COMMON_RECV_PRE_RET_DROP:
        case TCP_COMMON_RECV_PRE_RET_ACK_OF_RANGE:
            goto drop;
        default:
            break;
    }
    if(tcp_client_later_recv_is_fin(pcb, recv_pack_info))
        tcp_transmit_ctrl(pcb, TCP_FLAG_ACK, pcb->snd_nxt);

quit:
drop:
    return ;
}


static void tcp_close_wait_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info){
    int ret;
    
    ret = tcp_common_recv_pre_dispose(pcb, recv_pack_info);
    switch (ret) {
        case 0:
        case TCP_COMMON_RECV_PRE_RET_QUIT:
            goto quit;
        case TCP_COMMON_RECV_PRE_RET_ACK_OF_RANGE:
        case TCP_COMMON_RECV_PRE_RET_DROP:
            goto drop;
        default:
            break;
    }

    if(tcp_client_later_recv_is_fin(pcb, recv_pack_info))
        pcb->need_ack = 1;

    tcp_client_auto_send(pcb, recv_pack_info->opt_sack);

    if(pcb->need_ack){
        tcp_transmit_ctrl(pcb, TCP_FLAG_ACK, pcb->snd_nxt);
    }

    if(tcp_pcb_is_tx_channel_idle(pcb)){
        tcp_close_tx(pcb);
        tcp_client_send_fin(pcb, TCP_STATE_LAST_ACK);
        pcb->need_ack = 0;
    }
quit:
drop:
    return ;
}

static void tcp_last_ack_recv_dispose(struct tcp_pcb *pcb, struct tcp_recv_pack_info *recv_pack_info){
    int ret;
    
    ret = tcp_common_recv_pre_dispose(pcb, recv_pack_info);
    switch (ret) {
        case TCP_COMMON_RECV_PRE_RET_QUIT:
            goto quit;
        case TCP_COMMON_RECV_PRE_RET_DROP:
        case TCP_COMMON_RECV_PRE_RET_ACK_OF_RANGE:
            goto drop;
        default:
            break;
    }

    if(tcp_client_later_recv_is_fin(pcb, recv_pack_info))
        tcp_transmit_ctrl(pcb, TCP_FLAG_ACK, pcb->snd_nxt);

    if(ret){
        tcp_interior_try_close(pcb, TCP_DISCONNECTED);
    }

drop:
quit:
    return ;
}

static struct tcp_server_pcb* tcp_listen_syn_match(const struct tcp_hash_key *_key){
    struct tcp_hash_key key = *_key;
    int ret;
    struct eh_hashtbl_node *node;

    key.remote_addr = IPV4_ADDR_ANY;
    key.remote_port = 0;
    /* 尝试用 src_ip src_port net_dev匹配 */
    ret = eh_hashtbl_find(tcp_hash_tbl, &key, sizeof(struct tcp_hash_key), &node);
    if(ret == 0){
        return (struct tcp_server_pcb*)((struct tcp_hash_value*)eh_hashtbl_node_value(node))->pcb;
    }

    key.local_addr = IPV4_ADDR_ANY;
    /* 尝试用 src_port net_dev匹配 */
    ret = eh_hashtbl_find(tcp_hash_tbl, &key, sizeof(struct tcp_hash_key), &node);
    if(ret == 0){
        return (struct tcp_server_pcb*)((struct tcp_hash_value*)eh_hashtbl_node_value(node))->pcb;
    }

    key.netdev = NULL;
    /* 尝试用 src_port 匹配 */
    ret = eh_hashtbl_find(tcp_hash_tbl, &key, sizeof(struct tcp_hash_key), &node);
    if(ret == 0){
        return (struct tcp_server_pcb*)((struct tcp_hash_value*)eh_hashtbl_node_value(node))->pcb;
    }
    return NULL;
}

static void tcp_connect_info_init(struct tcp_pcb *pcb){
    ehip_netdev_t *netdev = tcp_pcb_to_netdev(pcb);
    eh_ringbuf_clear(pcb->rx_buf);
    eh_ringbuf_clear(pcb->tx_buf);
    memset(&pcb->rx_fragment_info, 0, sizeof(pcb->rx_fragment_info));
    pcb->ts_recent = 0;
    pcb->rx_fragment_info.frag_tab[0] = (uint16_t)eh_ringbuf_free_size(pcb->rx_buf);
    pcb->rx_fragment_info.window_size = pcb->rx_fragment_info.frag_tab[0];
    pcb->rx_fragment_info.fin = 0;
    pcb->rx_fragment_info.frag_tab_len = 1;
    pcb->flags = 0;
    pcb->snd_una = ((uint32_t)eh_get_clock_monotonic_time() ^ pcb->node->hash_val);
    pcb->mss = netdev->attr.mtu - (uint16_t)(sizeof(struct ip_hdr) + sizeof(struct tcp_hdr));
    pcb->srtt = 0;
    pcb->departure_time = 0;
    pcb->cwnd = 1;
    pcb->ssthresh = TCP_INIT_SSTHRESH;
    pcb->rto = TCP_INIT_RTO;
}


static int tcp_connect(struct tcp_pcb *pcb, bool is_client){
    int ret;
    ret = tcp_open_tx(pcb);
    if(ret < 0)
        goto error;
    ret = tcp_open_rx(pcb);
    if(ret < 0)
        goto error;

    ret = tcp_route_refresh(pcb);
    if(ret < 0)
        goto error;

    if(pcb->state == TCP_STATE_TIME_WAIT){
        /* 处于TIME_WAIT状态的pcb，需要从hashtbl中删除 */
        tcp_pcb_hashtbl_uninstall(pcb->node);
    }

    ret = tcp_pcb_hashtbl_install(pcb->node, pcb->config_flags & TCP_PCB_PRIVATE_FLAGS_AUTO_PORT);
    if(ret < 0)
        goto error;

    tcp_connect_info_init(pcb);
    
    ret = tcp_transmit_syn(pcb, !is_client, pcb->snd_una);
    if(ret < 0)
        goto error;
    pcb->snd_nxt = pcb->snd_una + 1;
    pcb->state = is_client ? TCP_STATE_SYN_SENT : TCP_STATE_SYN_RECEIVED;
    tcp_stop_simple_timer(pcb);
    tcp_start_simple_timer(pcb, TCP_TIMEOUT_CONNECT_SIGNAL, TCP_TIMEOUT_CONNECT_DOWNCNT, TCP_TIMEOUT_CONNECT_RETRY);
    return 0;
error:
    tcp_close_rx(pcb);
    tcp_close_tx(pcb);
    return ret;
}

static void server_new_connect_change_callback(tcp_pcb_t _pcb, enum tcp_event state){
    struct tcp_pcb *pcb = (struct tcp_pcb *)_pcb;
    struct tcp_server_pcb *server_pcb = ehip_tcp_client_get_userdata(_pcb);
    if(state != TCP_CONNECTED){
        /* 这里假装是用户在关闭 */
        tcp_close(pcb, true);
    }else{
        ehip_tcp_client_set_userdata(_pcb, NULL);
        ehip_tcp_set_events_callback(_pcb, NULL);
        if(server_pcb->opt.new_connect)
            server_pcb->opt.new_connect(_pcb);
        tcp_client_events_callback(pcb, TCP_CONNECTED);
    }
}


void tcp_input(struct ip_message *ip_msg){
    struct tcp_hdr *tcp_hdr;
    ehip_buffer_t *tcp_msg;
    struct pseudo_header pseudo_hdr;
    uint16_t checksum = 0;
    ehip_buffer_size_t tcp_data_len;
    struct tcp_hash_key key;
    ehip_netdev_t *input_netdev;
    struct eh_hashtbl_node *node;
    int ret;
    struct tcp_pcb *pcb;
    struct tcp_server_pcb *server_pcb;
    struct tcp_recv_pack_info recv_pack_info;

    if(ip_message_flag_is_fragment(ip_msg)){
        ehip_buffer_t *first_buf;
        ehip_buffer_t *pos_buffer;
        uint8_t *copy_ptr;
        int tmp_i;
        ehip_buffer_size_t single_copy_size;

        /* 合并分片到 tcp_msg中，方便后续处理 */
        first_buf = ip_message_rx_fragment_first(ip_msg);
        /* 
         * 将rx data和 first_buf的总容量进行对比，因为我们即将从first_buf身上进行dup，
         * 这样便于我们提前知道buf的空间够不够,如果单帧buffer的空间不够，那说明对面TCP设备
         * 没有按MSS来，我们直接丢弃即可
         */
        tcp_data_len = (ehip_buffer_size_t)ip_message_rx_data_size(ip_msg);
        if( tcp_data_len > ehip_buffer_get_buffer_size(first_buf)){
            goto drop;
        }
        tcp_msg = ehip_buffer_new(ehip_buffer_get_buffer_type(first_buf), 0);
        if(eh_ptr_to_error(tcp_msg) < 0){
            goto drop;
        }
        copy_ptr = ehip_buffer_payload_append(tcp_msg, tcp_data_len);
        ip_message_tx_fragment_for_each(pos_buffer, tmp_i, ip_msg){
            single_copy_size = ehip_buffer_get_payload_size(pos_buffer);
            memcpy(copy_ptr, ehip_buffer_get_payload_ptr(pos_buffer), single_copy_size);
            copy_ptr += single_copy_size;
        }
        input_netdev = first_buf->netdev;

    }else{
        ehip_buffer_t *first_buf;

        first_buf = ip_message_first(ip_msg);
        input_netdev = first_buf->netdev;
        tcp_msg = ehip_buffer_ref_dup(first_buf);
        if(eh_ptr_to_error(tcp_msg) < 0)
            goto drop;
    }

    tcp_hdr = (struct tcp_hdr *)ehip_buffer_get_payload_ptr(tcp_msg);

    /* 进行tcp基础校验 */
    tcp_data_len = ehip_buffer_get_payload_size(tcp_msg);
    if(tcp_data_len < sizeof(struct tcp_hdr) || tcp_data_len < tcp_hdr_size(tcp_hdr)){
        eh_mwarnfl(TCP_INPUT, "tcp msg too small %d", tcp_data_len);
        goto checksum_error;
    }
    if(tcp_hdr->doff < 5){
        eh_mwarnfl(TCP_INPUT, "tcp msg doff %d invalid", tcp_hdr->doff);
        goto checksum_error;
    }
    pseudo_hdr.src_addr = ip_msg->ip_hdr.src_addr;
    pseudo_hdr.dst_addr = ip_msg->ip_hdr.dst_addr;
    pseudo_hdr.zero = 0;
    pseudo_hdr.proto = IP_PROTO_TCP;
    pseudo_hdr.len = eh_hton16(tcp_data_len);
    checksum = ehip_inet_chksum_accumulated(checksum, &pseudo_hdr, sizeof(struct pseudo_header));
    checksum = ehip_inet_chksum_accumulated(checksum, tcp_hdr, tcp_data_len);
    if(checksum != 0){
        eh_mwarnfl(TCP_INPUT, "tcp msg checksum error %#hx", tcp_hdr->check);
        goto checksum_error;
    }

    eh_mdebugfl(TCP_INPUT, "(%d->%d) s:%u a:%u f:%04x l:%d", 
        eh_ntoh16(tcp_hdr->source), eh_hton16(tcp_hdr->dest),
        eh_ntoh32(tcp_hdr->seq), eh_ntoh32(tcp_hdr->ack_seq),
        eh_ntoh16(tcp_hdr->flags), tcp_recv_data_len(tcp_msg, tcp_hdr));

    key.local_port = tcp_hdr->dest;
    key.remote_port = tcp_hdr->source;
    key.local_addr = ip_msg->ip_hdr.dst_addr;
    key.remote_addr = ip_msg->ip_hdr.src_addr;
    key.netdev = input_netdev;
    /* 5元组精确匹配 */
    /* 通过HASH来找tcp_pcb */
    ret = eh_hashtbl_find(tcp_hash_tbl, &key, sizeof(struct tcp_hash_key), &node);
    if(ret == 0){
        pcb = (struct tcp_pcb *)((struct tcp_hash_value*)eh_hashtbl_node_value(node))->pcb;

        ip_message_free(ip_msg);

        if(pcb->state < TCP_STATE_MAX){
            tcp_recv_pack_info_init(&recv_pack_info, tcp_msg, tcp_hdr);
            tcp_state_recv_dispose_tab[pcb->state](pcb, &recv_pack_info);
        }else{
            eh_mwarnfl(TCP_INPUT, "tcp state %d not support", pcb->state);
        }
        ehip_buffer_free(tcp_msg);
        return ;
    }

    if(!tcp_hdr->syn || tcp_hdr->rst)
        goto eh_hashtbl_find_error;

    if(tcp_hdr->source == 0 || tcp_hdr->dest == 0)
        goto eh_hashtbl_find_error;
    
    /* 处理syn 匹配server */
    server_pcb = tcp_listen_syn_match(&key);
    if(server_pcb == NULL){
        goto eh_tcp_port_unreachable;
    }

    /* new一个tcp_pcb来处理三次握手 */
    pcb = (struct tcp_pcb *)tcp_pcb_base_new(TCP_PCB_PRIVATE_FLAGS_ANY, &key, server_pcb->rx_buffer_size, server_pcb->tx_buffer_size);
    if(eh_ptr_to_error(pcb) < 0){
        eh_mwarnfl(TCP_INPUT, "tcp_pcb_base_new error %d", eh_ptr_to_error(pcb));
        goto tcp_pcb_base_new_error;
    }
    ip_message_free(ip_msg);
    
    ehip_tcp_client_set_userdata((tcp_pcb_t)pcb, server_pcb);
    ehip_tcp_set_events_callback((tcp_pcb_t)pcb, server_new_connect_change_callback);
    pcb->state = TCP_STATE_LISTEN;
    tcp_recv_pack_info_init(&recv_pack_info, tcp_msg, tcp_hdr);
    tcp_state_recv_dispose_tab[pcb->state](pcb, &recv_pack_info);
    ehip_buffer_free(tcp_msg);
    return ;
tcp_pcb_base_new_error:
eh_tcp_port_unreachable:
    /* 应该回复RST TODO */
eh_hashtbl_find_error:
checksum_error:
    ehip_buffer_free(tcp_msg);
drop:
    ip_message_free(ip_msg);
    return ;
}

int ehip_tcp_client_request_send(tcp_pcb_t _pcb){
    struct tcp_pcb *pcb = (struct tcp_pcb *)_pcb;
    /* 检查是否处于可进行数据发送的状态 */
    if(pcb->state != TCP_STATE_ESTABLISHED && pcb->state != TCP_STATE_CLOSE_WAIT)
        return EH_RET_INVALID_STATE;
    
    pcb->user_req_transmit = 1;

    if(pcb->later_transmit || pcb->retransmit || pcb->sack_retransmit){
        return 0;
    }
    return tcp_client_data_send(pcb);
}

tcp_pcb_t ehip_tcp_client_new(ipv4_addr_t bind_addr, uint16_be_t bind_port, 
    ehip_netdev_t *netdev, ipv4_addr_t dst_addr, uint16_be_t dst_port, uint16_t rx_buf_size, uint16_t tx_buf_size){
    struct tcp_hash_key key;
    if( !netdev || ehip_netdev_trait_ipv4_dev(netdev)== NULL || 
        ipv4_is_global_bcast(bind_addr) || ipv4_is_global_bcast(dst_addr) || dst_port == 0 || 
        rx_buf_size <= 0){
        return eh_error_to_ptr(EH_RET_INVALID_PARAM);
    }
    key.local_port = bind_port;
    key.remote_port = dst_port;
    key.local_addr = bind_addr;
    key.remote_addr = dst_addr;
    key.netdev = netdev;
    return tcp_pcb_base_new(0, &key, rx_buf_size, tx_buf_size);
}

tcp_pcb_t ehip_tcp_client_any_new(uint16_be_t bind_port, ipv4_addr_t dst_addr, 
    uint16_be_t dst_port, uint16_t rx_buf_size, uint16_t tx_buf_size){
    struct tcp_hash_key key;
    if( ipv4_is_global_bcast(dst_addr) || dst_port == 0 || 
        rx_buf_size <= 0){
        return eh_error_to_ptr(EH_RET_INVALID_PARAM);
    }
    key.local_port = bind_port;
    key.remote_port = dst_port;
    key.local_addr = IPV4_ADDR_ANY;
    key.remote_addr = dst_addr;
    key.netdev = NULL;
    return tcp_pcb_base_new(TCP_PCB_PRIVATE_FLAGS_ANY, &key, rx_buf_size, tx_buf_size);
}


void ehip_tcp_client_delete(tcp_pcb_t pcb){
    ehip_tcp_client_disconnect(pcb);
    tcp_close((struct tcp_pcb *)pcb, true);
}


void ehip_tcp_client_get_info(tcp_pcb_t _pcb, tcp_client_info_t *info){
    struct tcp_pcb *pcb = (struct tcp_pcb *)_pcb;
    const struct tcp_hash_key *key;
    key = (const struct tcp_hash_key *)eh_hashtbl_node_const_key(pcb->node);
    info->local_addr = key->local_addr;
    info->remote_addr = key->remote_addr;
    info->netdev = key->netdev;
    info->local_port = eh_ntoh16(key->local_port);
    info->remote_port = eh_ntoh16(key->remote_port);
}


int ehip_tcp_client_connect(tcp_pcb_t _pcb){
    struct tcp_pcb *pcb = (struct tcp_pcb *)_pcb;

    if(pcb == NULL || pcb->node == NULL)
        return EH_RET_INVALID_PARAM;

    if(pcb->state != TCP_STATE_CLOSED && pcb->state != TCP_STATE_TIME_WAIT){
        return EH_RET_INVALID_STATE;
    }

    return tcp_connect(pcb, true);
}


int ehip_tcp_client_disconnect(tcp_pcb_t _pcb){
    struct tcp_pcb *pcb = (struct tcp_pcb *)_pcb;
    if(pcb == NULL || pcb->node == NULL)
        return EH_RET_INVALID_PARAM;

    if(pcb->state != TCP_STATE_ESTABLISHED && pcb->state != TCP_STATE_SYN_RECEIVED){
        return EH_RET_INVALID_STATE;
    }
    if(pcb->user_req_disconnect)
        return 0;

    pcb->user_req_disconnect = 1;
    if(!tcp_pcb_is_tx_channel_idle(pcb))
        return 0;
    tcp_close_tx(pcb);
    tcp_client_send_fin(pcb, TCP_STATE_FIN_WAIT_1);
    return 0;
}



void ehip_tcp_client_set_userdata(tcp_pcb_t _pcb, void *userdata){
    struct tcp_pcb *pcb = (struct tcp_pcb *)_pcb;
    pcb->userdata = userdata;
}

void *ehip_tcp_client_get_userdata(tcp_pcb_t _pcb){
    struct tcp_pcb *pcb = (struct tcp_pcb *)_pcb;
    return pcb->userdata;
}


eh_ringbuf_t *ehip_tcp_client_get_send_ringbuf(tcp_pcb_t _pcb){
    struct tcp_pcb *pcb = (struct tcp_pcb *)_pcb;
    return pcb->tx_buf;
}
eh_ringbuf_t *ehip_tcp_client_get_recv_ringbuf(tcp_pcb_t _pcb){
    struct tcp_pcb *pcb = (struct tcp_pcb *)_pcb;
    return pcb->rx_buf;
}

void ehip_tcp_set_events_callback(tcp_pcb_t _pcb,
    void (*events_callback)(tcp_pcb_t pcb, enum tcp_event state)){
    struct tcp_pcb *pcb = (struct tcp_pcb *)_pcb;
    pcb->opt.events_callback = events_callback;
}


tcp_server_pcb_t ehip_tcp_server_new(ipv4_addr_t bind_addr, uint16_be_t bind_port, ehip_netdev_t *netdev, uint16_t rx_buf_size, uint16_t tx_buf_size){
    struct tcp_server_pcb *pcb = eh_malloc(sizeof(struct tcp_server_pcb));
    struct tcp_hash_key key;
    memset(pcb, 0, sizeof(struct tcp_server_pcb));
    pcb->rx_buffer_size = rx_buf_size;
    pcb->tx_buffer_size = tx_buf_size;
    // pcb->node = ehip_node_new(netdev, bind_addr, bind_port);
    key.remote_addr = IPV4_ADDR_ANY;
    key.remote_port = 0;
    key.local_addr = bind_addr;
    key.local_port = bind_port;
    key.netdev = netdev;
    pcb->node = eh_hashtbl_node_new_refresh(NULL, &key, sizeof(key), sizeof(struct tcp_hash_value));
    if(pcb->node == NULL){
        goto eh_hashtbl_node_new_refresh_error;
    }
    ((struct tcp_hash_value*)eh_hashtbl_node_value(pcb->node))->pcb = pcb;
    
    return (tcp_server_pcb_t)pcb;
eh_hashtbl_node_new_refresh_error:
    eh_free(pcb);
    return NULL;
}

tcp_server_pcb_t ehip_tcp_server_any_new(uint16_be_t bind_port, uint16_t rx_buf_size, uint16_t tx_buf_size){
    return ehip_tcp_server_new(IPV4_ADDR_ANY, bind_port, NULL, rx_buf_size, tx_buf_size);
}


void ehip_tcp_server_delete(tcp_server_pcb_t _pcb){
    struct tcp_server_pcb *pcb = (struct tcp_server_pcb *)_pcb;
    tcp_pcb_hashtbl_uninstall(pcb->node);
    eh_hashtbl_node_delete(NULL, pcb->node);
    eh_free(pcb);
}


int ehip_tcp_server_listen(tcp_server_pcb_t _pcb){
    struct tcp_server_pcb *pcb = (struct tcp_server_pcb *)_pcb;
    return tcp_pcb_hashtbl_install(pcb->node, false);
}


void ehip_tcp_server_set_new_connect_callback(tcp_server_pcb_t _pcb, void (*new_connect)(tcp_pcb_t new_client)){
    struct tcp_server_pcb *pcb = (struct tcp_server_pcb *)_pcb;
    pcb->opt.new_connect = new_connect;
}




static int tcp_init(void){
    tcp_hash_tbl = eh_hashtbl_create(EH_HASHTBL_DEFAULT_LOADFACTOR);
    if(eh_ptr_to_error(tcp_hash_tbl) < 0)
        return eh_ptr_to_error(tcp_hash_tbl);
    return 0;
}

static void tcp_exit(void){
    eh_hashtbl_destroy(tcp_hash_tbl);
}


ehip_protocol_module_export(tcp_init, tcp_exit);

