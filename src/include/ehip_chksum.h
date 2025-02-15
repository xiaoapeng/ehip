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

extern uint16_t ehip_standard_chksum(uint16_t sum_init, const void *dataptr, int len);

static inline uint16_t ehip_inet_chksum(const void *dataptr, int len)
{
    return ~ehip_standard_chksum(0x0000, dataptr, len);
    
}
static inline uint16_t ehip_inet_chksum_accumulated(uint16_t sum_init, const void *dataptr, int len)
{
    return ~ehip_standard_chksum(~sum_init, dataptr, len);
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _EHIP_CHKSUM_H_