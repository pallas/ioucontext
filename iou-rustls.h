// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_RUSTLS_TLS_H
#define IOUCONTEXT_RUSTLS_TLS_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct reactor_s reactor_t;
typedef int rustls_io_result;
struct rustls_connection;
struct rustls_server_config;
struct rustls_client_config_builder;

struct rustls_connection * iou_rustls_accept(reactor_t *, int fd, const struct rustls_server_config *);
struct rustls_connection * iou_rustls_connect(reactor_t *, int fd, struct rustls_client_config_builder *, const char * host);

ssize_t iou_rustls_read(reactor_t *, int fd, struct rustls_connection *, uint8_t *buf, size_t len);
ssize_t iou_rustls_write(reactor_t *, int fd, struct rustls_connection *, const uint8_t *buf, size_t len);
rustls_io_result iou_rustls_flush(reactor_t *, int fd, struct rustls_connection *);
rustls_io_result iou_rustls_shutdown(reactor_t *, int fd, struct rustls_connection *);

rustls_io_result iou_rustls_close(reactor_t *, int fd, struct rustls_connection *);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_RUSTLS_TLS_H
