// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_ARES_DNS_H
#define IOUCONTEXT_ARES_DNS_H

#include <stdarg.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct reactor_s reactor_t;
typedef struct ares_channeldata ares_channel_t;
struct ares_options;

typedef struct iou_ares_data_s {
    reactor_t * reactor;
    ares_channel_t * channel;
    int epfd;
    unsigned waiters;
} iou_ares_data_t;

ares_channel_t * iou_ares_get(reactor_t *, iou_ares_data_t * data, const struct ares_options * options, int optmask);
void iou_ares_put(iou_ares_data_t * data);

typedef struct todo_sigjmp_s todo_sigjmp_t;

typedef struct iou_ares_future_s {
    iou_ares_data_t * data;
    todo_sigjmp_t * todo;
} iou_ares_future_t;

int iou_ares__wait(iou_ares_future_t * result, ...);
#define iou_ares_wait(...) iou_ares__wait(__VA_ARGS__, (iou_ares_future_t *)NULL)

struct ares_addrinfo;
struct ares_addrinfo_hints;

typedef struct iou_ares_addr_result_s {
    iou_ares_future_t future;
    int status;
    int timeouts;
    struct ares_addrinfo * addrinfo;
} iou_ares_addr_result_t;

iou_ares_addr_result_t * iou_ares_addrinfo(
    iou_ares_data_t * data,
    const char *name, const char *service,
    const struct ares_addrinfo_hints *hints,
    iou_ares_addr_result_t * result);

typedef struct iou_ares_name_result_s {
    iou_ares_future_t future;
    int status;
    int timeouts;
    char * node;
    char * service;
} iou_ares_name_result_t;

iou_ares_name_result_t * iou_ares_nameinfo(
    iou_ares_data_t * data,
    const struct sockaddr * sockaddr, socklen_t socklen,
    int flags,
    iou_ares_name_result_t * result);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_ARES_DNS_H
