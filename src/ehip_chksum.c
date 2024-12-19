/**
 * @file ehip_chksum.c
 * @brief 校验算法的实现
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2024-12-19
 * 
 * @copyright Copyright (c) 2024  simon.xiaoapeng@gmail.com
 * 
 */

#include <stdint.h>
#include <eh_swab.h>


#ifndef FOLD_U32T
#define FOLD_U32T(u)          ((uint32_t)(((u) >> 16) + ((u) & 0x0000ffffUL)))
#endif

#ifndef SWAP_BYTES_IN_WORD
#define SWAP_BYTES_IN_WORD(w) eh_swab16(w)
#endif


uint16_t ehip_standard_chksum(const void *dataptr, int len){
    const uint8_t *pos = (const uint8_t *)dataptr;
    const uint8_t *end = pos + len;
    int odd = ((uintptr_t)pos & 1);
    uint16_t tmp0 = 0;
    uint32_t sum = 0, tmp1;
    
    if(odd && len > 0)
        ((uint8_t *)&tmp0)[1] = *pos++;

    if((uintptr_t)pos & 3 && (end - pos) > 1){
        sum += *(uint16_t*)pos;
        pos += 2;
    }

    while(end - pos > 7){
        tmp1 = sum + *(uint32_t*)pos;
        if (tmp1 < sum)
            tmp1++;
        pos += 4;

        sum = tmp1 + *(uint32_t*)pos;
        if (sum < tmp1)
            sum++;
        pos += 4;
    }

    sum = FOLD_U32T(sum);

    while (end - pos > 1) {
        sum += *(uint16_t*)pos;
        pos += 2;
    }

    if (end - pos > 0) {
        ((uint8_t *)&tmp0)[0] = *pos;
        pos++;
    }
    sum += tmp0;

    sum = FOLD_U32T(sum);
    sum = FOLD_U32T(sum);

    if(odd)
        sum = SWAP_BYTES_IN_WORD(sum);

    return (uint16_t)sum;
}
