// SPDX-License-Identifier: MIT
#define _GNU_SOURCE

#include <ioucontext/ioucontext.h>

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
    bool shutdown;
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
        if (TRY(iou_read, reactor, sfd, &si, sizeof si) < sizeof si)
            abort();
    } while (!sigismember(mask, si.ssi_signo));
    TRY(sigprocmask, SIG_UNBLOCK, mask, NULL);

    iou_close(reactor, sfd);

    cookie_t *cookie = (cookie_t*)reactor_cookie(reactor);
    cookie->shutdown = true;

    fd_t *cancelation;
    LIST_FOREACH(cancelation, &cookie->cancelations, entries) {
        int fd = cancelation->fd;
        iou_printf(reactor, STDERR_FILENO, "cancel fd %d\n", fd);
        iou_cancel_fd_all(reactor, cancelation->fd);
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
udp_service(reactor_t * reactor, const char * name, uint16_t port) {
    struct sockaddr_storage ss;
    if (!sockaddr_parse(&ss, name, port))
        abort();

    char s[sockaddr_address_size];
    if (sockaddr_unparse((struct sockaddr*)&ss, s, sizeof s))
        iou_printf(reactor, STDERR_FILENO, "udp starting on %s port %d\n", s, port);

    int fd = TRY(iou_socket, reactor, ss.ss_family, SOCK_DGRAM, 0);

    cookie_t *cookie = (cookie_t*)reactor_cookie(reactor);

    fd_t cancelation = { .fd = fd, };
    LIST_INSERT_HEAD(&cookie->cancelations, &cancelation, entries);
    iou_printf(reactor, STDERR_FILENO, "insert %p\n", &cancelation);

    TRY(iou_setsockopt_int, reactor, fd, SOL_SOCKET, SO_REUSEADDR, true);
    TRY(iou_setsockopt_int, reactor, fd, SOL_SOCKET, SO_REUSEPORT, true);
    TRY(iou_bind, reactor, fd, (struct sockaddr *)&ss, sizeof ss);

    while (iou_poll_in(reactor, fd, timespec_block)) {
        char buf[65535];
        int n = TRY(iou_recvfrom, reactor, fd, buf, sizeof buf, 0, (struct sockaddr *)&ss, sizeof ss);
        if (sockaddr_unparse((struct sockaddr*)&ss, s, sizeof s))
            iou_printf(reactor, STDERR_FILENO, "udp recv %d bytes from %s\n", n, s);
        n = TRY(iou_sendto, reactor, fd, buf, n, 0, (struct sockaddr *)&ss, sizeof ss);
    }

    LIST_REMOVE(&cancelation, entries);
    iou_printf(reactor, STDERR_FILENO, "remove %p\n", &cancelation);
    if (LIST_EMPTY(&cookie->cancelations))
        kill(0, SIGHUP);

    TRY(iou_close, reactor, fd);
}

void
tcp_service(reactor_t * reactor, const char * name, uint16_t port, void(*handler)(reactor_t *, int)) {
    struct sockaddr_storage ss;
    if (!sockaddr_parse(&ss, name, port))
        abort();

    char s[sockaddr_address_size];
    if (sockaddr_unparse((struct sockaddr*)&ss, s, sizeof s))
        iou_printf(reactor, STDERR_FILENO, "tcp starting on %s port %d\n", s, port);

    int fd = TRY(iou_socket, reactor, ss.ss_family, SOCK_STREAM, 0);

    cookie_t *cookie = (cookie_t*)reactor_cookie(reactor);

    fd_t cancelation = { .fd = fd, };
    LIST_INSERT_HEAD(&cookie->cancelations, &cancelation, entries);
    iou_printf(reactor, STDERR_FILENO, "insert %p\n", &cancelation);

    TRY(iou_setsockopt_int, reactor, fd, SOL_SOCKET, SO_REUSEADDR, true);
    TRY(iou_setsockopt_int, reactor, fd, SOL_SOCKET, SO_REUSEPORT, true);
    TRY(iou_bind, reactor, fd, (struct sockaddr *)&ss, sizeof ss);
    TRY(iou_listen, reactor, fd, 64);

    while (!cookie->shutdown) {
        socklen_t len = sizeof ss;
        int afd = iou_accept(reactor, fd, (struct sockaddr *)&ss, &len, 0);
        if (afd < 0)
            break;

        if (sockaddr_unparse((struct sockaddr*)&ss, s, sizeof s))
            iou_printf(reactor, STDERR_FILENO, "tcp accept %s port %d\n", s, (int)(
                ss.ss_family == AF_INET ? ntohs(((struct sockaddr_in*)&ss)->sin_port) :
                ss.ss_family == AF_INET6 ? ntohs(((struct sockaddr_in6*)&ss)->sin6_port) :
                0
            ));

        handler(reactor, afd);
    }

    LIST_REMOVE(&cancelation, entries);
    iou_printf(reactor, STDERR_FILENO, "remove %p\n", &cancelation);
    if (LIST_EMPTY(&cookie->cancelations))
        kill(0, SIGHUP);

    TRY(iou_close, reactor, fd);
}

void
tcp_handler(reactor_t * reactor, int fd) {
    int pipes[2];
    TRY(pipe, pipes);

    int rcvbuf = iou_getsockopt_int(reactor, fd, SOL_SOCKET, SO_RCVBUF);
    if (rcvbuf > fcntl(pipes[1], F_GETPIPE_SZ))
        fcntl(pipes[1], F_SETPIPE_SZ, rcvbuf);

    int sndbuf = iou_getsockopt_int(reactor, fd, SOL_SOCKET, SO_SNDBUF);
    if (sndbuf > fcntl(pipes[0], F_GETPIPE_SZ))
        fcntl(pipes[0], F_SETPIPE_SZ, sndbuf);

    iou_printf(reactor, STDERR_FILENO, "handle fd=%d send=%d recv=%d\n", fd, rcvbuf, sndbuf);

    while (true) {
        ssize_t n = iou_splice(reactor, fd, pipes[1], rcvbuf);
        if (n <= 0)
            break;
        iou_printf(reactor, STDERR_FILENO, "fd %d splice in %zd bytes\n", fd, n);

        n = iou_splice_all(reactor, pipes[0], fd, n);
        if (n <= 0)
            break;
        iou_printf(reactor, STDERR_FILENO, "fd %d splice out %zd bytes\n", fd, n);
    }

    iou_printf(reactor, STDERR_FILENO, "fd %d close\n", fd);

    iou_shutdown_read(reactor, fd);
    TRY(iou_close, reactor, pipes[1]);

    TRY(iou_close, reactor, pipes[0]);
    iou_shutdown_write(reactor, fd);

    TRY(iou_close, reactor, fd);
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

    for (int i = 0 ; i < 64 ; ++i) {
        reactor_fiber(udp_service, reactor, "::", 12345);
        reactor_fiber(tcp_service, reactor, "::", 12345, tcp_handler);
    }
    reactor_fiber(signal_handler, reactor, &mask);

    reactor_run(reactor);
    reactor_cookie_eat(reactor);

    thrd_exit(0);
    return 0;
}

//
