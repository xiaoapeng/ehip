/**
 * @file ehip_chksum.h
 * @brief 
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-12-19
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */

#ifndef _EHIP_CHKSUM_H_
#define _EHIP_CHKSUM_H_


#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

#include <stdint.h>

extern uint16_t ehip_standard_chksum(const void *dataptr, int len);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _EHIP_CHKSUM_H_