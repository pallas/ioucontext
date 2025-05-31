// SPDX-License-Identifier: MIT
#include "rustls_tls.h"

#include "operations.h"
#include "timespec.h"

#include <errno.h>
#include <limits.h>
#include <rustls.h>


typedef struct iou_rustls_iodata_s {
    reactor_t * reactor;
    int fd;
} iou_rustls_iodata_t;

static rustls_io_result
iou_rustls_read_callback(void *userdata, uint8_t *buf, size_t n, size_t *out_n) {
    iou_rustls_iodata_t *iodata = (iou_rustls_iodata_t*)userdata;

    ssize_t result = iou_read(iodata->reactor, iodata->fd, buf, n);

    if (result < 0)
        return result;

    if (out_n)
        *out_n = result;

    return 0;
}

static rustls_io_result
iou_rustls_tls_in_fd(reactor_t * reactor, int fd, struct rustls_connection * connection) {
    size_t n;
    iou_rustls_iodata_t iodata = { .reactor = reactor, .fd = fd };
    rustls_io_result result = rustls_connection_read_tls(connection, iou_rustls_read_callback, &iodata, &n);
    if (result)
        return result;

    if (RUSTLS_RESULT_OK != rustls_connection_process_new_packets(connection))
        return -EINVAL;

    return n > 0 ? 0 : -EINVAL;
}

ssize_t
iou_rustls_read(reactor_t * reactor, int fd, struct rustls_connection * connection, uint8_t *buf, size_t len) {
    size_t n;

    rustls_result result;
    rustls_io_result io_result;
    do {
        result = rustls_connection_read(connection, buf, len, &n);
    } while (RUSTLS_RESULT_PLAINTEXT_EMPTY == result && !(io_result = iou_rustls_tls_in_fd(reactor, fd, connection)));

    if (RUSTLS_RESULT_PLAINTEXT_EMPTY == result)
        return io_result;

    if (RUSTLS_RESULT_UNEXPECTED_EOF == result)
        return -EPIPE;

    if (RUSTLS_RESULT_OK != result)
        return -EINVAL;

    return n;
}

static rustls_io_result
iou_rustls_write_vectored_callback(void *userdata, const struct rustls_iovec *iov, size_t n, size_t *out_n) {
    iou_rustls_iodata_t *iodata = (iou_rustls_iodata_t*)userdata;

    ssize_t result = iou_pwritev(iodata->reactor, iodata->fd, (const struct iovec *)iov, n, -1, 0);

    if (result < 0)
        return -result;

    if (out_n)
        *out_n = result;

    return 0;
}

static rustls_io_result
iou_rustls_tls_out_fd(reactor_t * reactor, int fd, struct rustls_connection * connection) {
    size_t n;
    iou_rustls_iodata_t iodata = { .reactor = reactor, .fd = fd };
    rustls_io_result result = rustls_connection_write_tls_vectored(connection, iou_rustls_write_vectored_callback, &iodata, &n);
    if (result)
        return result;

    return n > 0 ? 0 : -EINVAL;
}

ssize_t
iou_rustls_write(reactor_t * reactor, int fd, struct rustls_connection * connection, const uint8_t *buf, size_t len) {
    size_t total = 0;
    while (true) {
        size_t n;
        if (RUSTLS_RESULT_OK != rustls_connection_write(connection, buf + total, len - total, &n))
            return total ? total : -EINVAL;

        total += n;
        if (total == len)
            return total;

        rustls_io_result result = iou_rustls_tls_out_fd(reactor, fd, connection);
        if (result)
            return result;
    }
}

rustls_io_result
iou_rustls_flush(reactor_t * reactor, int fd, struct rustls_connection * connection) {
    while (rustls_connection_wants_write(connection)) {
        rustls_io_result result = iou_rustls_tls_out_fd(reactor, fd, connection);
        if (result)
            return result;
    }
    return 0;
}

rustls_io_result
iou_rustls_shutdown(reactor_t * reactor, int fd, struct rustls_connection * connection) {
    rustls_connection_send_close_notify(connection);
    return iou_rustls_flush(reactor, fd, connection);
}

rustls_io_result
iou_rustls_close(reactor_t * reactor, int fd, struct rustls_connection * connection) {
    rustls_connection_free(connection);
    return iou_close(reactor, fd);
}

static rustls_io_result
iou_rustls_process(reactor_t * reactor, int fd, struct rustls_connection * connection) {
    rustls_io_result result;

    result = iou_rustls_flush(reactor, fd, connection);
    if (result)
        return result;

    while (rustls_connection_wants_read(connection) && !rustls_connection_wants_write(connection)) {
        result = iou_rustls_tls_in_fd(reactor, fd, connection);
        if (result)
            return result;
    }
    return 0;
}

static rustls_io_result
iou_rustls_handshake(reactor_t * reactor, int fd, struct rustls_connection * connection) {
    while (rustls_connection_is_handshaking(connection)) {
        rustls_io_result result = iou_rustls_process(reactor, fd, connection);
        if (result)
            return result;
    }
    return 0;
}

static void
iou_rustls_log_callback(void *userdata, const struct rustls_log_params *params) {
    reactor_t * reactor = (reactor_t *)userdata;
    struct rustls_str level_str = rustls_log_level_str(params->level);
    iou_printf(reactor, STDERR_FILENO, "%.*s: %.*s\n"
    , level_str.len, level_str.data
    , params->message.len, params->message.data
    );
}

struct rustls_connection *
iou_rustls_accept(reactor_t * reactor, int fd, const struct rustls_server_config *config) {
    struct rustls_connection *connection;
    rustls_result result = rustls_server_connection_new(config, &connection);
    if (RUSTLS_RESULT_OK != result)
        return NULL;

    if (iou_rustls_handshake(reactor, fd, connection)) {
        iou_close_fast(reactor, fd);
        rustls_connection_free(connection);
        return NULL;
    }

    return connection;
}

struct rustls_connection *
iou_rustls_connect(reactor_t * reactor, int fd, struct rustls_client_config_builder *config_builder, const char *host) {
    const struct rustls_client_config *config;
    if (RUSTLS_RESULT_OK != rustls_client_config_builder_build(config_builder, &config))
        return NULL;

    struct rustls_connection *connection;
    rustls_result result = rustls_client_connection_new(config, host, &connection);
    rustls_client_config_free(config);
    if (RUSTLS_RESULT_OK != result)
        return NULL;

    if (iou_rustls_handshake(reactor, fd, connection)) {
        iou_close_fast(reactor, fd);
        rustls_connection_free(connection);
        return NULL;
    }

    return connection;
}

//
