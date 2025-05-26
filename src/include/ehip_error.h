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
#define EHIP_RET_UNREACHABLE           ((EH_RET_EHIP_ERROR_START) - 1)  /* -257  网络不可达 */
#define EHIP_RET_HOST_UNREACHABLE      ((EH_RET_EHIP_ERROR_START) - 2)  /* -258  主机不可达 */
#define EHIP_RET_PROTOCOL_UNREACHABLE  ((EH_RET_EHIP_ERROR_START) - 3)  /* -259  协议不可达 */
#define EHIP_RET_PORT_UNREACHABLE      ((EH_RET_EHIP_ERROR_START) - 4)  /* -260  端口不可达 */
#define EHIP_RET_FRAG_NEEDED           ((EH_RET_EHIP_ERROR_START) - 5)  /* -261  发送的数据报太长 */
#define EHIP_RET_SRC_ROUTE_FAILED      ((EH_RET_EHIP_ERROR_START) - 6)  /* -262  源路由失败 */
#define EHIP_RET_NET_UNKNOWN           ((EH_RET_EHIP_ERROR_START) - 7)  /* -263  目的网络未知 */
#define EHIP_RET_HOST_UNKNOWN          ((EH_RET_EHIP_ERROR_START) - 8)  /* -264  目的主机未知 */
#define EHIP_RET_SRC_HOST_ISOLATED     ((EH_RET_EHIP_ERROR_START) - 9)  /* -265  源主机被隔离 */
#define EHIP_RET_NET_PROHIBITED        ((EH_RET_EHIP_ERROR_START) - 10) /* -266  目的网络被禁止 */
#define EHIP_RET_HOST_PROHIBITED       ((EH_RET_EHIP_ERROR_START) - 11) /* -267  目的主机被禁止 */
#define EHIP_RET_REDIRECTED            ((EH_RET_EHIP_ERROR_START) - 12) /* -268  重定向 */
#define EHIP_RET_TTL_EXPIRED           ((EH_RET_EHIP_ERROR_START) - 13) /* -269  TTL过期，或者分片组合超时 */
#define EHIP_RET_PARAMETERPROB         ((EH_RET_EHIP_ERROR_START) - 14) /* -270  参数错误 */
#define EHIP_RET_SRC_PORT_BUSY         ((EH_RET_EHIP_ERROR_START) - 15) /* -271  源端口被占用 */





#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif // _EHIP_ERROR_H_