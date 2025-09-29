// SPDX-License-Identifier: MIT

#include "sockaddr.h"

#include <arpa/inet.h>
#include <string.h>

socklen_t
sockaddr_parse(struct sockaddr_storage *ss, const char *address, uint16_t port) {

    struct sockaddr_in *sin = (struct sockaddr_in*)ss;
    if (inet_pton(AF_INET, address, &sin->sin_addr) > 0) {
        ss->ss_family = AF_INET;
        sin->sin_port = htons(port);
        return sizeof *sin;
    }

    struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)ss;
    if (inet_pton(AF_INET6, address, &sin6->sin6_addr) > 0) {
        ss->ss_family = AF_INET6;
        sin6->sin6_port = htons(port);
        return sizeof *sin6;
    }

    return 0;
}

bool
sockaddr_unparse(const struct sockaddr *sa, char *buf, socklen_t len) {
    switch(sa->sa_family) {

    case AF_INET: {
        struct sockaddr_in *sin = (struct sockaddr_in*)sa;
        return !!inet_ntop(sin->sin_family, &sin->sin_addr, buf, len);
    }

    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
        return !!inet_ntop(sin6->sin6_family, &sin6->sin6_addr, buf, len);
    }
        
    default:
        return false;
    }
}

//
