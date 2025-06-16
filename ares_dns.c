// SPDX-License-Identifier: MIT
#include "ares_dns.h"

#include "reactor-internal.h"
#include "fiber.h"
#include "macros.h"
#include "operations.h"
#include "todo_sigjmp.h"

#include <ares.h>
#include <assert.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/epoll.h>

static void
iou_ares_sock_state_cb(void *data, int socket_fd, int readable, int writable) {
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)data;

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
    assert(!iou_ares_data->pending_writes);
    ++iou_ares_data->pending_writes;
}

static void
iou_ares_flush_pending_writes(iou_ares_data_t * iou_ares_data) {
    if (iou_ares_data->pending_writes) do {
        assert(iou_ares_data->pending_writes == 1);
        ares_process_pending_write(iou_ares_data->channel);
    } while (--iou_ares_data->pending_writes);
}

static ares_socket_t
iou_ares_asocket(int domain, int type, int protocol, void *user_data) {
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)user_data;
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

    assert(!address || address_len);
    assert(iou_poll_in(iou_ares_data->reactor, sock, timespec_zero));
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

    assert(!address || address_len);
    assert(iou_poll_out(reactor_synchronize(iou_ares_data->reactor), sock, timespec_zero));
    return address
        ? ERRNO(iou_sendto, reactor_synchronize(iou_ares_data->reactor), sock, buffer, length, flags, address, address_len)
        : ERRNO(iou_send, reactor_synchronize(iou_ares_data->reactor), sock, buffer, length, flags);
        ;
}

static int
iou_ares_agetsockname(ares_socket_t sock,
    struct sockaddr *address, ares_socklen_t *address_len,
    void *user_data)
{
    return getsockname(sock, address, address_len);
}

static int
iou_ares_abind(ares_socket_t sock,
    unsigned int flags,
    const struct sockaddr *address, socklen_t address_len,
    void *user_data)
{
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)user_data;
    assert(!address || address_len);
    return ERRNO(iou_bind, iou_ares_data->reactor, sock, address, address_len);
}

static unsigned int
iou_ares_aif_nametoindex(const char *ifname, void *user_data) {
    return if_nametoindex(ifname);
}

static const char *
iou_ares_aif_indextoname(unsigned int ifindex,
    char *ifname_buf, size_t ifname_buf_len,
    void *user_data)
{
    if (UNLIKELY(ifname_buf_len < IFNAMSIZ))
        return NULL;
    assert(ifname_buf_len >= IFNAMSIZ);
    return if_indextoname(ifindex, ifname_buf);
}

static const struct ares_socket_functions_ex iou_ares_socket_functions_ex = {
    .version = 1,
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
    ares_cancel(data->channel);
}

void
iou_ares_put(iou_ares_data_t * data) {
    ares_destroy(data->channel);
    assert(0 == data->waiters);
    assert(0 == data->pending_writes);
    close(data->epfd);
}

static void
iou_ares_future_fulfill(iou_ares_future_t * future) {
    if (future->todo) {
        reactor_schedule(future->data->reactor, &future->todo->jump);
        future->todo = NULL;
    }
    assert(future->data);
    future->data = NULL;
}

static void
iou_ares_search_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    iou_ares_result_t * result = (iou_ares_result_t *)arg;

    result->status = abuf ? ares_dns_parse(abuf, alen, result->flags, &result->dnsrec) : status;
    result->timeouts = timeouts;

    iou_ares_future_fulfill(&result->future);
}

iou_ares_result_t *
iou_ares_search(iou_ares_data_t * data, const char *name, int dnsclass, int type, unsigned int flags, iou_ares_result_t * result) {
    *result = (iou_ares_result_t) {
        .future = { .data = data },
        .flags = flags,
    };
    ares_search(data->channel, name, dnsclass, type, iou_ares_search_callback, result);
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
    ares_getaddrinfo(data->channel, name, service, hints, iou_ares_addrinfo_callback, result);
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
    ares_getnameinfo(data->channel, sockaddr, socklen, flags, iou_ares_nameinfo_callback, result);
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

static bool
iou_ares_resolve_any(iou_ares_data_t * data) {
    iou_ares_flush_pending_writes(data);

    struct timeval timeout = { };
    if (!ares_timeout(data->channel, NULL, &timeout))
        return false;

    if (!iou_poll_in(data->reactor, data->epfd, timeval_to_timespec(timeout))) {
        ares_process_fd(data->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        return true;
    }

    struct epoll_event events[32];
    int nfds;
    do { } while ((nfds = epoll_wait(data->epfd, events, sizeof(events)/sizeof(*events), 0)) < 0 && errno == EINTR);

    if (nfds == 0)
        iou_yield(data->reactor);
    else if (nfds > 0)
        for (int i = 0 ; i < nfds ; ++i) {
            int fd = events[i].data.fd;
            bool read = events[i].events & EPOLLIN;
            bool write = events[i].events & EPOLLOUT;

            // assert(!read || iou_poll_in(data->reactor, fd, timespec_zero));
            // assert(!write || iou_poll_out(data->reactor, fd, timespec_zero));

            ares_process_fd(data->channel
            , read ? fd : ARES_SOCKET_BAD
            , write ? fd : ARES_SOCKET_BAD
            );
        }

    return nfds > 0;
}

static void
iou_ares_resolve_one(iou_ares_future_t * future) {
    while (future->data)
        iou_ares_resolve_any(future->data);
}

static void
iou_ares_resolve_all(reactor_t * reactor, iou_ares_data_t * data) {
    assert(reactor == data->reactor);
    while (iou_ares_resolve_any(data)) { }
    --data->waiters;
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
                if (future->data)
                    iou_ares_resolve_one(future);
                future = va_arg(list, iou_ares_future_t *);
            } while (future && (!future->data || future->data == data));

            if (data->waiters > 1)
                reactor_fiber(iou_ares_resolve_all, data->reactor, data);
            else
                --data->waiters;
        } else {
            todo_sigjmp_t todo;
            future->todo = &todo;
            if (!sigsetjmp(*make_todo_sigjmp(&todo, data->reactor->current), false))
                reactor_enter_core(data->reactor);

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
