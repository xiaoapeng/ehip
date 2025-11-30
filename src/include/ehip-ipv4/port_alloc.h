/**
 * @file port_alloc.h
 * @brief 端口分配器
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-11-26
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */
#ifndef _PORT_ALLOC_H_
#define _PORT_ALLOC_H_


#include <eh_swab.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

/**
 * @brief                   随机分配一个端口
 * @return uint16_be_t      端口号
 */
extern uint16_be_t ehip_bind_port_alloc(void);


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _PORT_ALLOC_H_