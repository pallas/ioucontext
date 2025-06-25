// SPDX-License-Identifier: MIT
#define _GNU_SOURCE

#include <ioucontext/ioucontext.h>
#include <ioucontext/iou-cares.h>
#include <ioucontext/iou-rustls.h>

#include <ares.h>
#include <assert.h>
#include <rustls.h>
#include <sched.h>
#include <string.h>
#include <threads.h>

void
rustls_egress(reactor_t * reactor, int fd, struct rustls_connection * connection, int from) {
    uint8_t buffer[PIPE_BUF];
    while (true) {
        ssize_t n_in = iou_read(reactor, from, buffer, sizeof buffer);
        if (n_in <= 0)
            break;

        ssize_t n_out = iou_rustls_write(reactor, fd, connection, buffer, n_in);
        if (n_out < n_in)
            break;

        iou_rustls_flush(reactor, fd, connection);
    }

    iou_rustls_shutdown(reactor, fd, connection);
}

void
rustls_ingress(reactor_t * reactor, int fd, struct rustls_connection * connection, int into) {
    uint8_t buffer[PIPE_BUF];
    while (true) {
        ssize_t n_in = iou_rustls_read(reactor, fd, connection, buffer, sizeof buffer);
        if (n_in <= 0)
            break;

        ssize_t n_out = iou_write(reactor, into, buffer, n_in);
        if (n_out < n_in)
            break;
    }
}

int
main(int argc, char *argv[]) {
    cpu_set_t cpu_set;
    CPU_ZERO_S(sizeof(cpu_set_t), &cpu_set);
    CPU_SET_S(0, sizeof(cpu_set_t), &cpu_set);
    TRY(sched_setaffinity, 0, sizeof(cpu_set_t), &cpu_set);

    reactor_t * reactor = reactor_get();

    const char *default_ca_bundles[] = {
        "/etc/ssl/certs/ca-certificates.crt",
    };
    const char * ca_bundle = getenv("IOUCONTEXT_CA_BUNDLE");
    for (int i = 0 ; !ca_bundle && i < sizeof(default_ca_bundles)/sizeof(*default_ca_bundles) ; ++i)
        if (iou_exists(reactor, default_ca_bundles[i]))
            ca_bundle = default_ca_bundles[i];

    const struct rustls_root_cert_store *root_cert_store = NULL;
    if (ca_bundle) {
        rustls_result result;
        struct rustls_root_cert_store_builder *builder = rustls_root_cert_store_builder_new();
        result = rustls_root_cert_store_builder_load_roots_from_file(builder, ca_bundle, true);
        if (RUSTLS_RESULT_OK != result)
            abort();
        result = rustls_root_cert_store_builder_build(builder, &root_cert_store);
        if (RUSTLS_RESULT_OK != result)
            abort();
        rustls_root_cert_store_builder_free(builder);
    }

    struct rustls_server_cert_verifier *server_cert_verifier = NULL;
    if (root_cert_store) {
        rustls_result result;
        struct rustls_web_pki_server_cert_verifier_builder *builder = rustls_web_pki_server_cert_verifier_builder_new(root_cert_store);
        result = rustls_web_pki_server_cert_verifier_builder_build(builder, &server_cert_verifier);
        if (RUSTLS_RESULT_OK != result)
            abort();
        rustls_web_pki_server_cert_verifier_builder_free(builder);
    }

    TRY(ares_library_init, ARES_LIB_INIT_ALL);

    iou_ares_data_t iou_ares_data;
    if (!iou_ares_get(reactor, &iou_ares_data, NULL, 0))
        abort();

    iou_ares_addr_result_t addr_results[argc];
    const struct ares_addrinfo_hints addrinfo_hints = {
        .ai_flags = ARES_AI_NOSORT,
        .ai_socktype = SOCK_STREAM,
    };
    for (int i = 1 ; i < argc ; ++i) {
        char *service = NULL;
        char *host = strtok_r(argv[i], "/", &service);
        iou_ares_addrinfo(&iou_ares_data, host, service ?: "echo", &addrinfo_hints, &addr_results[i]);
    }

    int fd;
    struct rustls_connection * connection = NULL;

    for (int i = 1 ; i < argc ; ++i) {
        iou_ares_wait(&addr_results[i].future);
        if (ARES_SUCCESS != addr_results[i].status || !addr_results[i].addrinfo)
            continue;

        if (!connection)
            fd = iou_ares_dial(reactor, addr_results[i].addrinfo, timespec_from_double(1.5));

        iou_ares_addr_free(&addr_results[i]);

        if (fd < 0)
            continue;

        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);
        TRY(getpeername, fd, (struct sockaddr *)&addr, &addrlen);

        char buf[sockaddr_address_size];
        if (sockaddr_unparse((const struct sockaddr *)&addr, buf, sizeof buf))
            iou_printf(reactor, STDERR_FILENO, "connect to %s %s/%d\n", argv[i], buf, (int)(
                addr.ss_family == AF_INET ? ntohs(((struct sockaddr_in*)&addr)->sin_port) :
                addr.ss_family == AF_INET6 ? ntohs(((struct sockaddr_in6*)&addr)->sin6_port) :
                0
            ));

        struct rustls_client_config_builder *client_config_builder = rustls_client_config_builder_new();
        if (server_cert_verifier)
            rustls_client_config_builder_set_server_verifier(client_config_builder, server_cert_verifier);
        rustls_client_config_builder_set_enable_sni(client_config_builder, true);

        connection = iou_rustls_connect(reactor, fd, client_config_builder, argv[i]);
        if (connection)
            iou_ares_cancel(&iou_ares_data);
        else
            iou_close_fast(reactor, fd);
    }

    iou_ares_put(&iou_ares_data);
    ares_library_cleanup();

    if (connection) {
        reactor_fiber(rustls_egress, reactor, fd, connection, STDIN_FILENO);
        reactor_fiber(rustls_ingress, reactor, fd, connection, STDOUT_FILENO);
        reactor_run(reactor);
        iou_rustls_close(reactor, fd, connection);
    }

    rustls_server_cert_verifier_free(server_cert_verifier);
    rustls_root_cert_store_free(root_cert_store);

    thrd_exit(connection ? 0 : EXIT_FAILURE);
    return 0;
}

//
