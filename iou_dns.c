// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include "ioucontext.h"

#include <ares.h>
#include <netdb.h>

void
forward_dns(reactor_t * reactor, iou_ares_data_t * iou_ares_data, const char * name) {
    iou_ares_addr_result_t result;
    const struct ares_addrinfo_hints hints = {
        .ai_flags = ARES_AI_NOSORT,
    };
    iou_ares_addrinfo(iou_ares_data, name, NULL, &hints, &result);
    iou_ares_wait(&result.future);

    if (ARES_SUCCESS != result.status)
        return;


    for_ares_addrinfo_cnames(cname, *result.addrinfo)
        iou_printf(reactor, STDOUT_FILENO, "%s is %s\n", cname->alias, cname->name);

    for_ares_addrinfo_nodes(node, *result.addrinfo) {
        char buf[sockaddr_address_size];
        if (sockaddr_unparse(node->ai_addr, buf, sizeof buf))
            iou_printf(reactor, STDOUT_FILENO, "%s is %s\n", result.addrinfo->name, buf);
    }

    iou_ares_addr_free(&result);
}

void
reverse_dns(reactor_t * reactor, iou_ares_data_t * iou_ares_data, const char * addr,
        struct sockaddr_storage * sockaddr, socklen_t socklen)
{
    iou_ares_name_result_t result;
    iou_ares_nameinfo(iou_ares_data, (struct sockaddr *)sockaddr, socklen, 0, &result);
    iou_ares_wait(&result.future);

    if (ARES_SUCCESS != result.status)
        return;

    iou_printf(reactor, STDOUT_FILENO, "%s is %s\n", addr, result.node ? result.node : "");

    iou_ares_name_free(&result);
}

void
resolve_dns(reactor_t * reactor, iou_ares_data_t * iou_ares_data, const char * name) {
    struct sockaddr_storage sockaddr;
    socklen_t socklen = sockaddr_parse(&sockaddr, name, 0);

    if (socklen)
        reverse_dns(reactor, iou_ares_data, name, &sockaddr, socklen);
    else
        forward_dns(reactor, iou_ares_data, name);
}

void
resolve_all(reactor_t * reactor, iou_ares_data_t * iou_ares_data, int argc, const char *argv[]) {
    for (int i = 1 ; i < argc ; ++i)
        reactor_fiber(resolve_dns, reactor, iou_ares_data, (char*)argv[i]);
}

int
main(int argc, const char *argv[]) {
    reactor_t * reactor = reactor_get();

    TRY(ares_library_init, ARES_LIB_INIT_ALL);

    iou_ares_data_t iou_ares_data;
    struct ares_options options = {
        .flags = ARES_FLAG_STAYOPEN | ARES_FLAG_EDNS | ARES_FLAG_DNS0x20,
    };
    ares_channel_t * channel = iou_ares_get(reactor, &iou_ares_data, &options, 0
    | ARES_OPT_FLAGS
    | ARES_OPT_ROTATE
    );

    reactor_fiber(resolve_all, reactor, &iou_ares_data, argc, argv);

    reactor_run(reactor);

    iou_ares_put(&iou_ares_data);
    ares_library_cleanup();
    return 0;
}
