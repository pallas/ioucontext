// SPDX-License-Identifier: MIT
#define _GNU_SOURCE

#include <ioucontext/ioucontext.h>
#include <ioucontext/iou-rustls.h>

#include <assert.h>
#include <fcntl.h>
#include <rustls.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
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
    const struct rustls_server_config *server_config;
} cookie_t;

void
cookie_eat(void *c) {
    cookie_t *cookie = (cookie_t*)c;
    fd_t *cancelation;
    assert(LIST_EMPTY(&cookie->cancelations));
    if (cookie->server_config)
        rustls_server_config_free(cookie->server_config);
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

    fd_t *cancelation;
    LIST_FOREACH(cancelation, &cookie->cancelations, entries) {
        int fd = cancelation->fd;
        iou_printf(reactor, STDERR_FILENO, "cancel fd %d\n", fd);
        iou_cancel_fd_all(reactor, cancelation->fd);
    }
}

typedef void(*tls_handler_t)(reactor_t *, int, struct rustls_connection *);

void
tls_service(reactor_t * reactor, const char * name, uint16_t port, const struct rustls_server_config *server_config, tls_handler_t handler) {
    struct sockaddr_storage ss;
    if (!sockaddr_parse(&ss, name, port))
        abort();

    char s[sockaddr_address_size];
    if (sockaddr_unparse((struct sockaddr*)&ss, s, sizeof s))
        iou_printf(reactor, STDERR_FILENO, "tls starting on %s port %d\n", s, port);

    int fd = TRY(iou_socket, reactor, ss.ss_family, SOCK_STREAM, 0);

    fd_t cancelation = { .fd = fd, };
    LIST_INSERT_HEAD(&((cookie_t*)reactor_cookie(reactor))->cancelations, &cancelation, entries);
    iou_printf(reactor, STDERR_FILENO, "insert %p\n", &cancelation);

    TRY(iou_setsockopt_int, reactor, fd, SOL_SOCKET, SO_REUSEADDR, true);
    TRY(iou_bind, reactor, fd, (struct sockaddr *)&ss, sizeof ss);
    TRY(iou_listen, reactor, fd, 64);

    while (true) {
        socklen_t len = sizeof ss;
        int afd = iou_accept(reactor, fd, (struct sockaddr *)&ss, &len);
        if (afd < 0)
            break;

        if (sockaddr_unparse((struct sockaddr*)&ss, s, sizeof s))
            iou_printf(reactor, STDERR_FILENO, "tls accept %s port %d\n", s, (int)(
                ss.ss_family == AF_INET ? ntohs(((struct sockaddr_in*)&ss)->sin_port) :
                ss.ss_family == AF_INET6 ? ntohs(((struct sockaddr_in6*)&ss)->sin6_port) :
                0
            ));

        struct rustls_connection * connection = iou_rustls_accept(reactor, afd, server_config);
        if (!connection)
            continue;

        reactor_fiber(handler, reactor, afd, connection);
    }

    LIST_REMOVE(&cancelation, entries);
    iou_printf(reactor, STDERR_FILENO, "remove %p\n", &cancelation);
    if (LIST_EMPTY(&((cookie_t*)reactor_cookie(reactor))->cancelations))
        kill(0, SIGHUP);

    TRY(iou_close, reactor, fd);
}

void
tls_handler(reactor_t * reactor, int fd, struct rustls_connection * connection) {
    uint8_t buffer[PIPE_BUF];
    while (true) {
        ssize_t n_in = iou_rustls_read(reactor, fd, connection, buffer, sizeof buffer);
        if (n_in <= 0)
            break;

        ssize_t n_out = iou_rustls_write(reactor, fd, connection, buffer, n_in);
        if (n_out < n_in)
            break;

        iou_rustls_flush(reactor, fd, connection);
    }

    iou_rustls_shutdown(reactor, fd, connection);
    iou_rustls_close(reactor, fd, connection);
}

uint8_t *
mmap_file(reactor_t * reactor, const char *pathname, size_t *size) {
    int fd = iou_open(reactor, pathname, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0)
        return NULL;

    void * data = NULL;
    ssize_t ssize = iou_fd_size(reactor, fd);

    if (ssize >= 0)
        data = mmap(NULL, (*size = ssize), PROT_READ, MAP_PRIVATE, fd, 0);

    close(fd);

    return MAP_FAILED != data ? data : NULL;
}

const struct rustls_certified_key *
load_certified_key(reactor_t * reactor, const char *cert, const char *key) {
    const struct rustls_certified_key *certified_key = NULL;

    size_t cert_size;
    uint8_t *cert_data = mmap_file(reactor, cert, &cert_size);
    if (!cert_data)
        iou_printf(reactor, STDERR_FILENO, "can not read %s\n", cert);

    size_t key_size;
    uint8_t *key_data = mmap_file(reactor, key, &key_size);
    if (!key_data)
        iou_printf(reactor, STDERR_FILENO, "can not read %s\n", key);

    if (cert_data && key_data) {
        rustls_result result = rustls_certified_key_build(cert_data, cert_size, key_data, key_size, &certified_key);
        if (RUSTLS_RESULT_OK != result)
            iou_printf(reactor, STDERR_FILENO, "can not parse certified_key from %s %s\n", cert, key);
    }

    if (cert_data)
        munmap(cert_data, cert_size);

    if (key_data)
        munmap(key_data, key_size);

    return certified_key;
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

    struct rustls_server_config_builder *server_config_builder = rustls_server_config_builder_new();

    size_t certified_keys_size = 0;
    const struct rustls_certified_key *certified_keys[argc];
    for (int i = 1 ; i < argc ; ++i) {
        char *rest = NULL;
        char *cert = strtok_r(argv[i], ",", &rest);
        char *key = strtok_r(NULL, ",", &rest);
        iou_printf(reactor, STDERR_FILENO, "%s %s\n", cert, key);

        certified_keys[certified_keys_size] = load_certified_key(reactor, cert, key);
        if (certified_keys[certified_keys_size])
            ++certified_keys_size;
    }

    if (certified_keys_size)
        rustls_server_config_builder_set_certified_keys(server_config_builder, certified_keys, certified_keys_size);

    while (certified_keys_size)
        rustls_certified_key_free(certified_keys[--certified_keys_size]);

    rustls_result result = rustls_server_config_builder_build(server_config_builder, &((cookie_t*)reactor_cookie(reactor))->server_config);
    if (RUSTLS_RESULT_OK != result)
        return result;

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGINT);
    TRY(sigprocmask, SIG_BLOCK, &mask, NULL);

    reactor_fiber(signal_handler, reactor, &mask);
    reactor_fiber(tls_service, reactor, "::", 12345, ((cookie_t*)reactor_cookie(reactor))->server_config, tls_handler);

    reactor_run(reactor);
    reactor_cookie_eat(reactor);

    thrd_exit(0);
    return 0;
}

//
