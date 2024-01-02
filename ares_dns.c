// SPDX-License-Identifier: MIT
#include "ares_dns.h"

#include "reactor-internal.h"
#include "fiber.h"
#include "macros.h"
#include "operations.h"
#include "todo_sigjmp.h"

#include <ares.h>
#include <string.h>
#include <assert.h>
#include <sys/epoll.h>

static void
iou_ares_sock_state_cb(void *data, int fd, int read, int write) {
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)data;

    struct epoll_event event = {
        .events = 0
            | (read ? EPOLLIN : 0)
            | (write ? EPOLLOUT : 0),
        .data.fd = fd,
    };

    if (event.events)
        TRY(iou_epoll_set, iou_ares_data->reactor, iou_ares_data->epfd, fd, &event);
    else
        TRY(iou_epoll_del, iou_ares_data->reactor, iou_ares_data->epfd, fd);
}

static ares_socket_t
iou_ares_asocket(int domain, int type, int protocol, void * user_data) {
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)user_data;
    int fd = ERRNO(iou_socket, iou_ares_data->reactor, domain, type, protocol);
    if (fd < 0)
        return fd;

    int flags = fcntl(fd, F_GETFL);
    if (!(O_NONBLOCK & flags))
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    return fd;
}

int
iou_ares_aclose(ares_socket_t fd, void * user_data) {
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)user_data;
    assert(-ENOENT == iou_epoll_del(iou_ares_data->reactor, iou_ares_data->epfd, fd));
    return ERRNO(iou_close, iou_ares_data->reactor, fd);
}

int
iou_ares_aconnect(ares_socket_t fd,
    const struct sockaddr * addr, ares_socklen_t addr_len,
    void * user_data)
{
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)user_data;
    return ERRNO(iou_connect, iou_ares_data->reactor, fd, addr, addr_len);
}

ares_ssize_t
iou_ares_arecvfrom(ares_socket_t fd,
    void * buffer, size_t buf_size,
    int flags,
    struct sockaddr * addr, ares_socklen_t * addr_len,
    void * user_data)
{
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)user_data;

    assert(addr_len || !addr);
    assert(iou_poll_in(iou_ares_data->reactor, fd, timespec_zero));
    return addr
        ? ERRNO(iou_recvfrom, iou_ares_data->reactor, fd, buffer, buf_size, flags, addr, *addr_len)
        : ERRNO(iou_recv, iou_ares_data->reactor, fd, buffer, buf_size, flags)
        ;
}

ares_ssize_t
iou_ares_asendv(ares_socket_t fd,
    const struct iovec * data, int len,
    void * user_data)
{
    iou_ares_data_t * iou_ares_data = (iou_ares_data_t *)user_data;

    ares_ssize_t n = 0;
    for (int i = 0 ; i < len ; ++i) {
        int r = ERRNO(iou_send, iou_ares_data->reactor, fd, data[i].iov_base, data[i].iov_len, 0);
        if (r < 0)
            return r;
        n += r;
    }

    return n;
}

static const struct ares_socket_functions iou_ares_socket_functions = {
    .asocket = iou_ares_asocket,
    .aclose = iou_ares_aclose,
    .aconnect = iou_ares_aconnect,
    .arecvfrom = iou_ares_arecvfrom,
    .asendv = iou_ares_asendv,
};

ares_channel_t *
iou_ares_get(reactor_t * reactor, iou_ares_data_t * data, const struct ares_options * options, int optmask) {
    *data = (iou_ares_data_t) {
        .reactor = reactor,
        .epfd = TRY(epoll_create1, EPOLL_CLOEXEC),
        .waiters = 0,
    };

    struct ares_options iou_options = *options;

    assert(!(optmask & ARES_OPT_SOCK_STATE_CB));
    iou_options.sock_state_cb = iou_ares_sock_state_cb;
    iou_options.sock_state_cb_data = data;

    TRY(ares_init_options, &data->channel, &iou_options, optmask | ARES_OPT_SOCK_STATE_CB);
    ares_set_socket_functions(data->channel, &iou_ares_socket_functions, data);
}

void
iou_ares_put(iou_ares_data_t * data) {
    ares_destroy(data->channel);
    assert(0 == data->waiters);
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

#include <stdio.h>

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

static struct timespec
timeval_to_timespec(struct timeval tv) {
    return (struct timespec) {
        .tv_sec = tv.tv_sec,
        .tv_nsec = tv.tv_usec * 1000,
    };
}

static bool
iou_ares_resolve_any(iou_ares_data_t * data) {
    struct timeval timeout = { };
    if (!ares_timeout(data->channel, NULL, &timeout))
        return false;

    if (!iou_poll_in(data->reactor, data->epfd, timeval_to_timespec(timeout))) {
        ares_process_fd(data->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        return true;
    }

    struct epoll_event event;
    if (epoll_wait(data->epfd, &event, 1, 0) < 1)
        return false;

    int fd = event.data.fd;
    bool read = event.events & EPOLLIN;
    bool write = event.events & EPOLLOUT;

    assert(!read || iou_poll_in(data->reactor, fd, timespec_zero));
    assert(!write || iou_poll_out(data->reactor, fd, timespec_zero));

    ares_process_fd(data->channel
    , read ? fd : ARES_SOCKET_BAD
    , write ? fd : ARES_SOCKET_BAD
    );

    return true;
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
            if (!sigsetjmp(*make_todo_sigjmp(&todo), false))
                reactor_enter_core(data->reactor);

            --data->waiters;
            assert(!future->data);
            future = va_arg(list, iou_ares_future_t *);
        }
    }

    va_end(list);
    return 0;
}

//
