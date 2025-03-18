/**
 * @file ip_tx.h
 * @brief 实现IP层发送功能
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-03-18
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */

#ifndef _IP_TX_H_
#define _IP_TX_H_

#include <ehip-ipv4/ip_message.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */


extern void ip_tx(struct ip_message *ip_msg);


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _IP_TX_H_