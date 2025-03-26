/**
 * @file ehip_error.h
 * @brief 定义一些EHIP的错误码
 * @author simon.xiaoapeng (simon.xiaoapeng@gmail.com)
 * @date 2025-03-23
 * 
 * @copyright Copyright (c) 2025  simon.xiaoapeng@gmail.com
 * 
 */
#ifndef _EHIP_ERROR_H_
#define _EHIP_ERROR_H_

#include <eh_error.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

#define EHIP_RET_ADDR_NOT_EXISTS       ((EH_RET_EHIP_ERROR_START) - 0)  /* -256  所绑定的IP地址不存在 */
#define EHIP_RET_UNREACHABLE           ((EH_RET_EHIP_ERROR_START) - 1)  /* -257  IPV4不可达 */




#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _EHIP_ERROR_H_