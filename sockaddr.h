// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_SOCKADDR_H
#define IOUCONTEXT_SOCKADDR_H

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

static const socklen_t sockaddr_address_size = sizeof(union {
    char inet[INET_ADDRSTRLEN];
    char inet6[INET6_ADDRSTRLEN];
});

socklen_t sockaddr_parse(struct sockaddr_storage *, const char *address, uint16_t port);
bool sockaddr_unparse(const struct sockaddr *, char *buf, socklen_t len);

#ifdef __cplusplus
}
#endif


#endif//IOUCONTEXT_SOCKADDR_H
