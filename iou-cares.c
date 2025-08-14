// SPDX-License-Identifier: MIT
#include "iou-cares.h"

#include "reactor.h"
#include "fiber.h"
#include "macros-internal.h"
#include "operations.h"
#include "timespec.h"

#include <ares.h>
#include <assert.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/epoll.h>

static void
iou_ares_sock_state_cb(void *data, int socket_fd, int readable, int writable) {
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)data;
    assert(iou_mutex_taken(iou_ares_data->reactor, &iou_ares_data->mutex));

    struct epoll_event event = {
        .events = 0
            | (readable ? EPOLLIN : 0)
            | (writable ? EPOLLOUT : 0),
        .data.fd = socket_fd,
    };
    TRY(iou_epoll_mod, iou_ares_data->reactor, iou_ares_data->epfd, socket_fd, &event);
}

static void
iou_ares_pending_write_cb(void *data) {
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)data;
    assert(iou_mutex_taken(iou_ares_data->reactor, &iou_ares_data->mutex));
    assert(!iou_ares_data->pending_writes);
    ++iou_ares_data->pending_writes;
}

static void
iou_ares_flush_pending_writes(iou_ares_data_t * iou_ares_data) {
    assert(iou_mutex_taken(iou_ares_data->reactor, &iou_ares_data->mutex));
    if (iou_ares_data->pending_writes) do {
        assert(iou_ares_data->pending_writes == 1);
        ares_process_pending_write(iou_ares_data->channel);
    } while (--iou_ares_data->pending_writes);
}

static ares_socket_t
iou_ares_asocket(int domain, int type, int protocol, void *user_data) {
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)user_data;
    assert(iou_mutex_taken(iou_ares_data->reactor, &iou_ares_data->mutex));
    type |= SOCK_NONBLOCK;
    type |= SOCK_CLOEXEC;
    int fd = ERRNO(iou_socket, iou_ares_data->reactor, domain, type, protocol);
    if (fd < 0)
        return ARES_SOCKET_BAD;

    struct epoll_event event = { .data.fd = fd };
    TRY(iou_epoll_add, iou_ares_data->reactor, iou_ares_data->epfd, fd, &event);

    return fd;
}

static int
iou_ares_aclose(ares_socket_t sock, void *user_data) {
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)user_data;
    assert(iou_mutex_taken(iou_ares_data->reactor, &iou_ares_data->mutex));
    assert(ARES_SOCKET_BAD != sock);
    TRY(iou_epoll_del, iou_ares_data->reactor, iou_ares_data->epfd, sock);
    return ERRNO(iou_close, iou_ares_data->reactor, sock);
}

static int
iou_ares_asetsockopt(ares_socket_t sock,
    ares_socket_opt_t opt,
    const void *val, ares_socklen_t val_size,
    void *user_data)
{
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)user_data;
    assert(iou_mutex_taken(iou_ares_data->reactor, &iou_ares_data->mutex));

    switch (opt) {

    case ARES_SOCKET_OPT_SENDBUF_SIZE:
        assert(val_size == sizeof(int));
        return ERRNO(iou_setsockopt, iou_ares_data->reactor, sock, SOL_SOCKET, SO_SNDBUF, val, val_size);

    case ARES_SOCKET_OPT_RECVBUF_SIZE:
        assert(val_size == sizeof(int));
        return ERRNO(iou_setsockopt, iou_ares_data->reactor, sock, SOL_SOCKET, SO_RCVBUF, val, val_size);

    case ARES_SOCKET_OPT_BIND_DEVICE:
        return ERRNO(iou_setsockopt, iou_ares_data->reactor, sock, SOL_SOCKET, SO_BINDTODEVICE, val, val_size);

    case ARES_SOCKET_OPT_TCP_FASTOPEN:
        assert(val_size == sizeof(ares_bool_t));
        return ERRNO(iou_setsockopt_int, iou_ares_data->reactor, sock, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, ARES_TRUE == *(ares_bool_t*)val);

    default:
        errno = ENOPROTOOPT;
        return -1;
    }
}

static int
iou_ares_aconnect(ares_socket_t sock,
    const struct sockaddr *address, ares_socklen_t address_len,
    unsigned int flags,
    void *user_data)
{
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)user_data;
    assert(iou_mutex_taken(iou_ares_data->reactor, &iou_ares_data->mutex));

    if (flags & ARES_SOCKET_CONN_TCP_FASTOPEN) {
        int r = ERRNO(iou_setsockopt_int, iou_ares_data->reactor, sock, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, true);
        if (r < 0)
            return r;
    }

    return ERRNO(iou_connect, iou_ares_data->reactor, sock, address, address_len, timespec_block);
}

static ares_ssize_t
iou_ares_arecvfrom(ares_socket_t sock,
    void *buffer, size_t length,
    int flags,
    struct sockaddr *address, ares_socklen_t *address_len,
    void *user_data)
{
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)user_data;
    assert(iou_mutex_taken(iou_ares_data->reactor, &iou_ares_data->mutex));

    flags |= MSG_DONTWAIT;

    assert(!address || address_len);
    return address
        ? ERRNO(iou_recvfrom, iou_ares_data->reactor, sock, buffer, length, flags, address, *address_len)
        : ERRNO(iou_recv, iou_ares_data->reactor, sock, buffer, length, flags)
        ;
}

static ares_ssize_t
iou_ares_asendto(ares_socket_t sock,
    const void *buffer, size_t length,
    int flags,
    const struct sockaddr *address, ares_socklen_t address_len,
    void *user_data)
{
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)user_data;
    assert(iou_mutex_taken(iou_ares_data->reactor, &iou_ares_data->mutex));

    assert(!address || address_len);
    return address
        ? ERRNO(iou_sendto, iou_ares_data->reactor, sock, buffer, length, flags, address, address_len)
        : ERRNO(iou_send, iou_ares_data->reactor, sock, buffer, length, flags);
        ;
}

static int
iou_ares_agetsockname(ares_socket_t sock,
    struct sockaddr *address, ares_socklen_t *address_len,
    void *user_data)
{
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)user_data;
    assert(iou_mutex_taken(iou_ares_data->reactor, &iou_ares_data->mutex));
    return getsockname(sock, address, address_len);
}

static int
iou_ares_abind(ares_socket_t sock,
    unsigned int flags,
    const struct sockaddr *address, socklen_t address_len,
    void *user_data)
{
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)user_data;
    assert(iou_mutex_taken(iou_ares_data->reactor, &iou_ares_data->mutex));
    assert(!address || address_len);
    return ERRNO(iou_bind, iou_ares_data->reactor, sock, address, address_len);
}

static unsigned int
iou_ares_aif_nametoindex(const char *ifname, void *user_data) {
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)user_data;
    assert(iou_mutex_taken(iou_ares_data->reactor, &iou_ares_data->mutex));
    return if_nametoindex(ifname);
}

static const char *
iou_ares_aif_indextoname(unsigned int ifindex,
    char *ifname_buf, size_t ifname_buf_len,
    void *user_data)
{
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)user_data;
    assert(iou_mutex_taken(iou_ares_data->reactor, &iou_ares_data->mutex));
    if (UNLIKELY(ifname_buf_len < IFNAMSIZ))
        return NULL;
    assert(ifname_buf_len >= IFNAMSIZ);
    return if_indextoname(ifindex, ifname_buf);
}

static const struct ares_socket_functions_ex iou_ares_socket_functions_ex = {
    .version = 1,
    .flags = ARES_SOCKFUNC_FLAG_NONBLOCKING,
    .asocket = iou_ares_asocket,
    .aclose = iou_ares_aclose,
    .asetsockopt = iou_ares_asetsockopt,
    .aconnect = iou_ares_aconnect,
    .arecvfrom = iou_ares_arecvfrom,
    .asendto = iou_ares_asendto,
    .agetsockname = iou_ares_agetsockname,
    .abind = iou_ares_abind,
    .aif_nametoindex = iou_ares_aif_nametoindex,
    .aif_indextoname = iou_ares_aif_indextoname,
};

ares_channel_t *
iou_ares_get(reactor_t * reactor, iou_ares_data_t * data, const struct ares_options * options, int optmask) {
    *data = (iou_ares_data_t) {
        .reactor = reactor,
        .epfd = TRY(epoll_create1, EPOLL_CLOEXEC),
        .waiters = 0,
        .pending_writes = 0,
    };

    iou_mutex(&data->mutex);

    struct ares_options iou_options = options ? *options : (struct ares_options) { };

    assert(!(optmask & ARES_OPT_SOCK_STATE_CB));
    iou_options.sock_state_cb = iou_ares_sock_state_cb;
    iou_options.sock_state_cb_data = data;

    TRY(ares_init_options, &data->channel, &iou_options, optmask | ARES_OPT_SOCK_STATE_CB);
    ares_set_socket_functions_ex(data->channel, &iou_ares_socket_functions_ex, data);
    ares_set_pending_write_cb(data->channel, iou_ares_pending_write_cb, data);
}

void
iou_ares_cancel(iou_ares_data_t * data) {
    iou_mutex_enter(data->reactor, &data->mutex);
    ares_cancel(data->channel);
    iou_mutex_leave(data->reactor, &data->mutex);
}

void
iou_ares_put(iou_ares_data_t * data) {
    iou_mutex_enter(data->reactor, &data->mutex);
    assert(!ares_queue_active_queries(data->channel));
    ares_destroy(data->channel);
    iou_mutex_leave(data->reactor, &data->mutex);
    assert(0 == data->waiters);
    assert(0 == data->pending_writes);
    iou_close_fast(data->reactor, data->epfd);
}

static void
iou_ares_future_fulfill(iou_ares_future_t * future) {
    if (future->jump) {
        reactor_schedule(future->data->reactor, future->jump);
        future->jump = NULL;
    }
    assert(future->data);
    future->data = NULL;
}

static void
iou_ares_dnsrec_callback(void *arg, ares_status_t status, size_t timeouts, const struct ares_dns_record *dnsrec) {
    iou_ares_result_t * result = (iou_ares_result_t *)arg;

    result->status = status;
    result->timeouts = timeouts;
    if (ARES_SUCCESS == result->status)
        result->dnsrec = ares_dns_record_duplicate(dnsrec);

    iou_ares_future_fulfill(&result->future);
}

iou_ares_result_t *
iou_ares_query(iou_ares_data_t * data, const char *name, ares_dns_class_t dnsclass, ares_dns_rec_type_t type, unsigned short *qid, iou_ares_result_t * result) {
    *result = (iou_ares_result_t) {
        .future = { .data = data },
    };
    iou_mutex_enter(data->reactor, &data->mutex);
    result->status = ares_query_dnsrec(data->channel, name, dnsclass, type, iou_ares_dnsrec_callback, result, qid);
    iou_mutex_leave(data->reactor, &data->mutex);
    return result;
}

iou_ares_result_t *
iou_ares_search(iou_ares_data_t * data, const struct ares_dns_record *dnsrec, iou_ares_result_t * result) {
    *result = (iou_ares_result_t) {
        .future = { .data = data },
    };
    iou_mutex_enter(data->reactor, &data->mutex);
    result->status = ares_search_dnsrec(data->channel, dnsrec, iou_ares_dnsrec_callback, result);
    iou_mutex_leave(data->reactor, &data->mutex);
    return result;
}

void
iou_ares_result_free(iou_ares_result_t * result) {
    assert(!result->future.data);
    if (ARES_SUCCESS == result->status && result->dnsrec)
        ares_dns_record_destroy(result->dnsrec);
}

static void
iou_ares_addrinfo_callback(void *arg, int status, int timeouts, struct ares_addrinfo *addrinfo) {
    iou_ares_addr_result_t * result = (iou_ares_addr_result_t *)arg;

    result->status = status;
    result->timeouts = timeouts;
    result->addrinfo = addrinfo;

    iou_ares_future_fulfill(&result->future);
}

iou_ares_addr_result_t *
iou_ares_addrinfo(iou_ares_data_t * data, const char *name, const char *service, const struct ares_addrinfo_hints *hints, iou_ares_addr_result_t * result) {
    *result = (iou_ares_addr_result_t) {
        .future = { .data = data },
    };
    iou_mutex_enter(data->reactor, &data->mutex);
    ares_getaddrinfo(data->channel, name, service, hints, iou_ares_addrinfo_callback, result);
    iou_mutex_leave(data->reactor, &data->mutex);
    return result;
}

void
iou_ares_addr_free(iou_ares_addr_result_t * result) {
    assert(!result->future.data);
    if (ARES_SUCCESS == result->status && result->addrinfo)
        ares_freeaddrinfo(result->addrinfo);
}

static void
iou_ares_nameinfo_callback(void *arg, int status, int timeouts, char *node, char *service) {
    iou_ares_name_result_t * result = (iou_ares_name_result_t *)arg;

    result->status = status;
    result->timeouts = timeouts;
    result->node = node ? strdup(node) : NULL;
    result->service = service ? strdup(service) : NULL;

    iou_ares_future_fulfill(&result->future);
}

iou_ares_name_result_t *
iou_ares_nameinfo(iou_ares_data_t * data, const struct sockaddr *sockaddr, socklen_t socklen, int flags, iou_ares_name_result_t * result) {
    *result = (iou_ares_name_result_t) {
        .future = { .data = data },
    };
    iou_mutex_enter(data->reactor, &data->mutex);
    ares_getnameinfo(data->channel, sockaddr, socklen, flags, iou_ares_nameinfo_callback, result);
    iou_mutex_leave(data->reactor, &data->mutex);
    return result;
}

void
iou_ares_name_free(iou_ares_name_result_t * result) {
    assert(!result->future.data);
    if (ARES_SUCCESS == result->status) {
        free(result->node);
        free(result->service);
    }
}

static struct timespec
timeval_to_timespec(struct timeval tv) {
    return (struct timespec) {
        .tv_sec = tv.tv_sec,
        .tv_nsec = tv.tv_usec * 1000,
    };
}

static void
iou_ares_epoll_to_ares_fds(const struct epoll_event epoll_events[], ares_fd_events_t ares_fd_events[], size_t n_events) {
    for (size_t i = 0 ; i < n_events ; ++i) {
        const int fd = epoll_events[i].data.fd;
        const bool read = epoll_events[i].events & EPOLLIN;
        const bool write = epoll_events[i].events & EPOLLOUT;

        ares_fd_events[i] = (ares_fd_events_t){
            .fd = fd,
            .events = ARES_FD_EVENT_NONE
                | (read ? ARES_FD_EVENT_READ : 0)
                | (write ? ARES_FD_EVENT_WRITE : 0)
        };
    }
}

static bool
iou_ares_resolve_any(iou_ares_data_t * data, const void ** canary) {
    struct timeval timeout = { };
    if (!ares_timeout(data->channel, NULL, &timeout)) {
        assert(!ares_queue_active_queries(data->channel));
        assert(!data->pending_writes);
        return false;
    }

    assert(ares_queue_active_queries(data->channel));

    struct epoll_event events[32];
    static const size_t n_events = sizeof(events)/sizeof(*events);
    ares_fd_events_t fds[n_events];

    int nfds = iou_epoll_wait(data->reactor, data->epfd, events, n_events, timeval_to_timespec(timeout));
    while (n_events == nfds) {
        iou_ares_epoll_to_ares_fds(events, fds, nfds);

        iou_mutex_enter(data->reactor, &data->mutex);
        ares_process_fds(data->channel, fds, nfds, ARES_PROCESS_FLAG_SKIP_NON_FD);
        iou_mutex_leave(data->reactor, &data->mutex);

        nfds = (!canary || *canary) ? iou_epoll_wait(data->reactor, data->epfd, events, n_events, timespec_zero) : 0;
    }

    if (nfds < 0)
        nfds = 0;

    iou_ares_epoll_to_ares_fds(events, fds, nfds);

    iou_mutex_enter(data->reactor, &data->mutex);
    ares_process_fds(data->channel, fds, nfds, 0);
    iou_ares_flush_pending_writes(data);
    iou_mutex_leave(data->reactor, &data->mutex);

    return true;
}

static void
iou_ares_resolve_one(iou_ares_future_t * future) {
    while (future->data)
        if (UNLIKELY(!iou_ares_resolve_any(future->data, (const void**)&future->data)))
            abort();
}

static void
iou_ares_resolve_all(reactor_t * reactor, iou_ares_data_t * data) {
    assert(reactor == data->reactor);
    assert(ares_queue_active_queries(data->channel));
    while (iou_ares_resolve_any(data, NULL))
        iou_yield(reactor);
    --data->waiters;
    assert(!ares_queue_active_queries(data->channel));
}

int
iou_ares__wait(iou_ares_future_t * future, ...) {
    va_list list;
    va_start(list, future);

    while (future) {
        iou_ares_data_t * data = future->data;
        if (!future->data) {
            future = va_arg(list, iou_ares_future_t *);
        } else if (!data->waiters++) {
            do {
                iou_ares_resolve_one(future);
                future = va_arg(list, iou_ares_future_t *);
            } while (future && (!future->data || future->data == data));

            assert(data->waiters > 0);
            if (data->waiters > 1 || ares_queue_active_queries(data->channel))
                reactor_fiber(iou_ares_resolve_all, data->reactor, data);
            else
                data->waiters = 0;
        } else {
            reactor_park(data->reactor, &future->jump);
            --data->waiters;
            assert(!future->data);
            future = va_arg(list, iou_ares_future_t *);
        }
    }

    va_end(list);
    return 0;
}

int
iou_ares_dial(reactor_t * reactor, struct ares_addrinfo *addrinfo, struct timespec delta) {
    for_ares_addrinfo_nodes(node, *addrinfo) {
        int fd = iou_ares_dial_node(reactor, node, delta);
        if (fd >= 0)
            return fd;
    }
    return -ENETUNREACH;
}

int
iou_ares_dial_node(reactor_t * reactor, struct ares_addrinfo_node *node, struct timespec delta) {
    int fd = iou_socket(reactor, node->ai_family, node->ai_socktype, node->ai_protocol);
    if (fd < 0)
        return fd;

    int r = iou_connect(reactor, fd, node->ai_addr, node->ai_addrlen, delta);
    if (r < 0) {
        iou_close_fast(reactor, fd);
        return r;
    }

    return fd;
}

//
