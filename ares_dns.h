// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_ARES_DNS_H
#define IOUCONTEXT_ARES_DNS_H

#include <ares.h>
#include <ares_nameser.h>
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
    unsigned pending_writes;
} iou_ares_data_t;

ares_channel_t * iou_ares_get(reactor_t *, iou_ares_data_t * data, const struct ares_options * options, int optmask);
void iou_ares_cancel(iou_ares_data_t * data);
void iou_ares_put(iou_ares_data_t * data);

typedef struct jump_chain_s jump_chain_t;

typedef struct iou_ares_future_s {
    iou_ares_data_t * data;
    jump_chain_t * jump;
} iou_ares_future_t;

int iou_ares__wait(iou_ares_future_t * result, ...);
#define iou_ares_wait(...) iou_ares__wait(__VA_ARGS__, (iou_ares_future_t *)NULL)

struct ares_dns_record;

typedef struct iou_ares_result_s {
    iou_ares_future_t future;
    int status;
    int timeouts;
    struct ares_dns_record *dnsrec;
} iou_ares_result_t;

iou_ares_result_t * iou_ares_query(
    iou_ares_data_t * data,
    const char *name,
    ares_dns_class_t dnsclass,
    ares_dns_rec_type_t type,
    unsigned short *qid,
    iou_ares_result_t * result);

iou_ares_result_t * iou_ares_search(
    iou_ares_data_t * data,
    const struct ares_dns_record *dnsrec,
    iou_ares_result_t * result);

void iou_ares_result_free(iou_ares_result_t * result);

struct ares_addrinfo;
struct ares_addrinfo_hints;
struct ares_addrinfo_node;

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

int iou_ares_dial(reactor_t *, struct ares_addrinfo *addrinfo, struct timespec delta);
int iou_ares_dial_node(reactor_t *, struct ares_addrinfo_node *node, struct timespec delta);

#define for_ares_addrinfo_cnames(CNAME, ADDRINFO) \
    for (struct ares_addrinfo_cname * (CNAME) = (ADDRINFO).cnames ; (CNAME) ; (CNAME) = (CNAME)->next)
#define for_ares_addrinfo_nodes(NODE, ADDRINFO) \
    for (struct ares_addrinfo_node * (NODE) = (ADDRINFO).nodes ; (NODE) ; (NODE) = (NODE)->ai_next)

void iou_ares_addr_free(iou_ares_addr_result_t * result);

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

void iou_ares_name_free(iou_ares_name_result_t * result);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_ARES_DNS_H
