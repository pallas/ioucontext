// SPDX-License-Identifier: MIT
#define _GNU_SOURCE

#include "fiber.h"
#include "macros.h"
#include "operations.h"
#include "reactor.h"
#include "timespec.h"
#include "sockaddr.h"

#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/signalfd.h>
#include <threads.h>


struct fd_s;
typedef LIST_HEAD(fd_list_s, fd_s) fd_list_t;
typedef LIST_ENTRY(fd_s) fd_entry_t;

typedef struct fd_s {
    fd_entry_t entries;
    int fd;
} fd_t;

typedef struct cookie_s {
    fd_list_t cancelations;
} cookie_t;

void
cookie_eat(void *c) {
    cookie_t *cookie = (cookie_t*)c;
    fd_t *cancelation;
    assert(LIST_EMPTY(&cookie->cancelations));
}

void
signal_handler(reactor_t * reactor, sigset_t *mask) {
    int sfd = TRY(signalfd, -1, mask, 0);

    struct signalfd_siginfo si;
    explicit_bzero(&si, sizeof si);
    do {
        if (TRY(io_read, reactor, sfd, &si, sizeof si) < sizeof si)
            abort();
    } while (!sigismember(mask, si.ssi_signo));

    io_close(reactor, sfd);

    cookie_t *cookie = (cookie_t*)reactor_cookie(reactor);

    fd_t *cancelation;
    LIST_FOREACH(cancelation, &cookie->cancelations, entries) {
        int fd = cancelation->fd;
        io_printf(reactor, STDERR_FILENO, "cancel fd %d\n", fd);
        io_cancel_fd_all(reactor, cancelation->fd);
    }
}

static inline int min(int l, int r) { return l < r ? l : r; }
static inline int max(int l, int r) { return l > r ? l : r; }

int
max_pipe(int fd) {
    int size = fcntl(fd, F_GETPIPE_SZ);
    if (size < PIPE_BUF)
        return PIPE_BUF;

    while ((size = fcntl(fd, F_SETPIPE_SZ, size << 1)) > 0) { }

    return fcntl(fd, F_GETPIPE_SZ);
}

void
setsockint(int fd, int opt, int val) {
    TRY(setsockopt, fd, SOL_SOCKET, opt, &val, sizeof val);
}

int
getsockint(int fd, int opt) {
    int val;
    socklen_t len = sizeof val;
    TRY(getsockopt, fd, SOL_SOCKET, opt, &val, &len);
    assert(len == sizeof val);
    return val;
}

void
udp_service(reactor_t * reactor, const char * name, uint16_t port) {
    struct sockaddr_storage ss;
    if (!sockaddr_parse(&ss, name, port))
        abort();

    char s[sockaddr_address_size];
    if (sockaddr_unparse((struct sockaddr*)&ss, s, sizeof s))
        io_printf(reactor, STDERR_FILENO, "udp starting on %s port %d\n", s, port);

    int fd = TRY(io_socket, reactor, ss.ss_family, SOCK_DGRAM, 0);

    fd_t cancelation = { .fd = fd, };
    LIST_INSERT_HEAD(&((cookie_t*)reactor_cookie(reactor))->cancelations, &cancelation, entries);
    io_printf(reactor, STDERR_FILENO, "insert %p\n", &cancelation);

    setsockint(fd, SO_REUSEADDR, true);
    TRY(bind, fd, (struct sockaddr *)&ss, sizeof ss);

    while (io_poll_in(reactor, fd, timespec_block)) {
        char buf[65535];
        int n = TRY(io_recvfrom, reactor, fd, buf, sizeof buf, 0, (struct sockaddr *)&ss, sizeof ss);
        if (sockaddr_unparse((struct sockaddr*)&ss, s, sizeof s))
            io_printf(reactor, STDERR_FILENO, "udp recv %d bytes from %s\n", n, s);
        n = TRY(io_sendto, reactor, fd, buf, n, 0, (struct sockaddr *)&ss, sizeof ss);
    }

    LIST_REMOVE(&cancelation, entries);
    io_printf(reactor, STDERR_FILENO, "remove %p\n", &cancelation);
    if (LIST_EMPTY(&((cookie_t*)reactor_cookie(reactor))->cancelations))
        kill(0, SIGHUP);

    TRY(io_close, reactor, fd);
}

void
tcp_service(reactor_t * reactor, const char * name, uint16_t port, void(*handler)()) {
    struct sockaddr_storage ss;
    if (!sockaddr_parse(&ss, name, port))
        abort();

    char s[sockaddr_address_size];
    if (sockaddr_unparse((struct sockaddr*)&ss, s, sizeof s))
        io_printf(reactor, STDERR_FILENO, "tcp starting on %s port %d\n", s, port);

    int fd = TRY(io_socket, reactor, ss.ss_family, SOCK_STREAM, 0);

    fd_t cancelation = { .fd = fd, };
    LIST_INSERT_HEAD(&((cookie_t*)reactor_cookie(reactor))->cancelations, &cancelation, entries);
    io_printf(reactor, STDERR_FILENO, "insert %p\n", &cancelation);

    setsockint(fd, SO_REUSEADDR, true);
    TRY(bind, fd, (struct sockaddr *)&ss, sizeof ss);
    TRY(listen, fd, 64);

    while (true) {
        socklen_t len = sizeof ss;
        int afd = io_accept(reactor, fd, (struct sockaddr *)&ss, &len);
        if (afd < 0)
            break;

        if (sockaddr_unparse((struct sockaddr*)&ss, s, sizeof s))
            io_printf(reactor, STDERR_FILENO, "tcp accept %s port %d\n", s, port);

        reactor_fiber(handler, reactor, afd);
    }

    LIST_REMOVE(&cancelation, entries);
    io_printf(reactor, STDERR_FILENO, "remove %p\n", &cancelation);
    if (LIST_EMPTY(&((cookie_t*)reactor_cookie(reactor))->cancelations))
        kill(0, SIGHUP);

    TRY(io_close, reactor, fd);
}

void
tcp_handler(reactor_t * reactor, int fd) {
    int pipes[2];
    TRY(pipe, pipes);

    int rcvbuf = getsockint(fd, SO_RCVBUF);
    if (rcvbuf > fcntl(pipes[1], F_GETPIPE_SZ))
        fcntl(pipes[1], F_SETPIPE_SZ, rcvbuf);

    int sndbuf = getsockint(fd, SO_SNDBUF);
    if (sndbuf > fcntl(pipes[0], F_GETPIPE_SZ))
        fcntl(pipes[0], F_SETPIPE_SZ, sndbuf);

    io_printf(reactor, STDERR_FILENO, "handle fd=%d send=%d recv=%d\n", fd, rcvbuf, sndbuf);

    while (true) {
        ssize_t n = io_splice(reactor, fd, pipes[1], rcvbuf);
        if (n <= 0)
            break;
        io_printf(reactor, STDERR_FILENO, "fd %d splice in %zd bytes\n", fd, n);

        n = io_splice_all(reactor, pipes[0], fd, n);
        if (n <= 0)
            break;
        io_printf(reactor, STDERR_FILENO, "fd %d splice out %zd bytes\n", fd, n);
    }

    io_printf(reactor, STDERR_FILENO, "fd %d close\n", fd);

    io_shutdown_read(reactor, fd);
    TRY(io_close, reactor, pipes[1]);

    TRY(io_close, reactor, pipes[0]);
    io_shutdown_write(reactor, fd);

    TRY(io_close, reactor, fd);
}

int
main(int argc, char *argv[]) {
    cpu_set_t cpu_set;
    CPU_ZERO_S(sizeof(cpu_set_t), &cpu_set);
    CPU_SET_S(0, sizeof(cpu_set_t), &cpu_set);
    TRY(sched_setaffinity, 0, sizeof(cpu_set_t), &cpu_set);

    TRY(signal, SIGPIPE, SIG_IGN);

    reactor_t * reactor = reactor_get();

    cookie_t cookie = { .cancelations = LIST_HEAD_INITIALIZER(cancelations), };
    reactor_cookie_jar(reactor, &cookie, cookie_eat);

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGINT);
    TRY(sigprocmask, SIG_BLOCK, &mask, NULL);

    reactor_fiber(signal_handler, reactor, &mask);
    reactor_fiber(udp_service, reactor, "::", 12345);
    reactor_fiber(tcp_service, reactor, "::", 12345, tcp_handler);

    reactor_run(reactor);
    reactor_cookie_eat(reactor);

    thrd_exit(0);
    return 0;
}

//
