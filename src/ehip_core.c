/**
 * @file ehip_core.c
 * @brief ehip 核心程序
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-10-04
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */

#include <eh.h>
#include <eh_debug.h>
#include <eh_error.h>
#include <eh_module.h>
#include <eh_signal.h>
#include <eh_mem_pool.h>
#include <eh_llist.h>
#include <eh_timer.h>

#include <ehip_core.h>
#include <ehip_module.h>
#include <ehip_netdev.h>
#include <ehip_conf.h>
#include <ehip_buffer.h>
#include <ehip_protocol_handle.h>

/* 邮箱RX信号 */
EH_STATIC_SIGNAL(signal_mbox_rx);
/* 邮箱实体 */
static struct eh_llist_head mbox_rx;

static void  slot_function_mbox_rx(eh_event_t *e, void *slot_param){
    (void)slot_param;
    uint32_t process_num = 0;
    struct eh_llist_node *pos;
    ehip_buffer_t *netdev_buffer;
    while((pos = eh_llist_dequeue(&mbox_rx))){
        netdev_buffer = eh_llist_entry(pos, ehip_buffer_t, node);
        ehip_protocol_handle_dispatch(netdev_buffer);
        process_num++;
        if(process_num >= EHIP_MAX_PACKET_PROCESS_NUM){
            eh_signal_notify(eh_signal_from_event(e));
            break;
        }
    }
}
static EH_DEFINE_SLOT(slot_mbox_rx, slot_function_mbox_rx, NULL);

static void slot_function_start_xmit(eh_event_t *e, void *slot_param){
    uint32_t process_num = 0;
    ehip_netdev_t *netdev = slot_param;
    struct eh_llist_node *pos;
    ehip_buffer_t *netdev_buffer;
    ehip_buffer_t *netdev_buffer_ref;
    int ret;
    while((pos = eh_llist_peek(&netdev->tx_queue))){
        netdev_buffer = eh_llist_entry(pos, ehip_buffer_t, node);

        if(netdev->param->ops && netdev->param->ops->ndo_start_xmit){
            netdev_buffer_ref = ehip_buffer_ref_dup(netdev_buffer);
            if((ret = eh_ptr_to_error(netdev_buffer_ref)) < 0)
                goto busy_and_error;
            /* 这里视为tx_buf的所有权转让,ndo_start_xmit应该承担释放它的责任*/
            ret = netdev->param->ops->ndo_start_xmit(netdev, netdev_buffer_ref);
            if(ret != 0)
                goto busy_and_error;
        }
        eh_llist_dequeue(&netdev->tx_queue);
        ehip_buffer_free(netdev_buffer);
        process_num++;
        if(process_num >= EHIP_MAX_PACKET_PROCESS_NUM){
            eh_signal_notify(eh_signal_from_event(e));
            break;
        }
    }
    eh_event_flags_clear_bits_change_notify(eh_signal_to_custom_event(&netdev->signal_status), EHIP_NETDEV_STATUS_TX_BUSY);
    eh_timer_stop(eh_signal_to_custom_event(&netdev->signal_watchdog));
    return ;
busy_and_error:
    eh_event_flags_set_bits_change_notify(eh_signal_to_custom_event(&netdev->signal_status), EHIP_NETDEV_STATUS_TX_BUSY);
    eh_timer_start(eh_signal_to_custom_event(&netdev->signal_watchdog));
}

static void slot_function_watchdog_timeout(eh_event_t *e, void *slot_param){
    (void)e;
    ehip_netdev_t *netdev = slot_param;
    if(netdev->param->ops && netdev->param->ops->ndo_tx_timeout){
        netdev->param->ops->ndo_tx_timeout(netdev);
    }
}


int ehip_queue_tx(ehip_buffer_t *netdev_buf){
    eh_llist_enqueue(ehip_buffer_get_node(netdev_buf), &netdev_buf->netdev->tx_queue);

    /* 如果TX_BUSY,则直接返回，否则触发wake_up信号 */
    if(eh_event_flags_get(eh_signal_to_custom_event(&netdev_buf->netdev->signal_status)) & EHIP_NETDEV_STATUS_TX_BUSY)
        return 0;
    /* wake_up_tx */
    eh_signal_notify(&netdev_buf->netdev->signal_tx_wakeup);
    return 0;
}


void ehip_queue_tx_clean(ehip_netdev_t *netdev){
    struct eh_llist_node *pos;
    ehip_buffer_t *netdev_buffer;

    while((pos = eh_llist_dequeue(&netdev->tx_queue))){
        netdev_buffer = eh_llist_entry(pos, ehip_buffer_t, node);
        ehip_buffer_free(netdev_buffer);
    }
}

void ehip_queue_tx_wakeup(ehip_netdev_t *netdev){
    eh_signal_notify(&netdev->signal_tx_wakeup);
}

int ehip_rx(ehip_buffer_t *netdev_buf){
    eh_llist_enqueue(ehip_buffer_get_node(netdev_buf), &mbox_rx);
    eh_signal_notify(&signal_mbox_rx);
    return 0;
}


int  _ehip_core_netdev_init(ehip_netdev_t *netdev){
    int ret;
    eh_llist_head_init(&netdev->tx_queue);
    eh_signal_init(&netdev->signal_tx_wakeup);
    eh_signal_slot_init(&netdev->slot_tx_wakeup, slot_function_start_xmit, netdev);
    ret = eh_signal_slot_connect_to_main(&netdev->signal_tx_wakeup, &netdev->slot_tx_wakeup);
    if(ret < 0){
        goto eh_signal_slot_connect_error;
    }

    eh_signal_init(&netdev->signal_watchdog);
    eh_timer_advanced_init(
        eh_signal_to_custom_event(&netdev->signal_watchdog),
        (eh_sclock_t)eh_msec_to_clock(EHIP_NETDEV_TX_WATCHDOG_TIMEOUT), 
        0
    );

    eh_signal_slot_init(&netdev->slot_watchdog, slot_function_watchdog_timeout, netdev);
    ret = eh_signal_slot_connect_to_main(&netdev->signal_watchdog, &netdev->slot_watchdog);
    if(ret < 0){
        goto eh_signal_watchdog_connect_error;
    }

    return 0;
eh_signal_watchdog_connect_error:
    eh_signal_slot_disconnect(&netdev->signal_tx_wakeup, &netdev->slot_tx_wakeup);
eh_signal_slot_connect_error:
    /* 无需调用 eh_signal_clean */
    return ret;
}
void _ehip_core_netdev_exit(ehip_netdev_t *netdev){
    eh_signal_slot_disconnect(&netdev->signal_watchdog, &netdev->slot_watchdog);
    eh_timer_clean(eh_signal_to_custom_event(&netdev->signal_watchdog));
    eh_signal_slot_disconnect(&netdev->signal_tx_wakeup, &netdev->slot_tx_wakeup);
}

int  _ehip_core_netdev_up(ehip_netdev_t *netdev){
    eh_llist_head_init(&netdev->tx_queue);
    return 0;
}
void _ehip_core_netdev_down(ehip_netdev_t *netdev){
    ehip_queue_tx_clean(netdev);
    eh_timer_stop(eh_signal_to_custom_event(&netdev->signal_watchdog));
}

static void _ehip_mbox_msg_clean(void){
    struct eh_llist_node *pos;
    ehip_buffer_t *netdev_buffer;

    while((pos = eh_llist_dequeue(&mbox_rx))){
        netdev_buffer = eh_llist_entry(pos, ehip_buffer_t, node);
        ehip_buffer_free(netdev_buffer);
    }
}

static int __init ehip_core_init(void){
    int ret;

    /* 注册连接邮箱RX信号和槽 */
    ret = eh_signal_slot_connect_to_main(&signal_mbox_rx, &slot_mbox_rx);
    if(ret < 0) goto eh_signal_slot_connect_mbox_rx;
    eh_llist_head_init(&mbox_rx);
    
    return 0;
eh_signal_slot_connect_mbox_rx:
    return ret;
}

static void __exit ehip_core_exit(void){
    _ehip_mbox_msg_clean();

    eh_signal_slot_disconnect(&signal_mbox_rx, &slot_mbox_rx);
}

ehip_core_module_export(ehip_core_init, ehip_core_exit);