#define _GNU_SOURCE
#include "ioucontext.h"

#include <ares.h>
#include <netdb.h>

void
resolve_dns(reactor_t * reactor, iou_ares_data_t * iou_ares_data, const char * name) {
    iou_ares_addr_result_t result;
    iou_ares_addrinfo(iou_ares_data, name, NULL, NULL, &result);
    iou_ares_wait(&result.future);

    if (ARES_SUCCESS != result.status)
        return;

    for (struct ares_addrinfo_cname *cnames = result.addrinfo->cnames ; cnames ; cnames = cnames->next)
        iou_printf(reactor, STDOUT_FILENO, "%s is %s\n", cnames->alias, cnames->name);

    for (struct ares_addrinfo_node *nodes = result.addrinfo->nodes ; nodes ; nodes = nodes->ai_next) {
        char buf[sockaddr_address_size];
        if (sockaddr_unparse(nodes->ai_addr, buf, sizeof buf))
            iou_printf(reactor, STDOUT_FILENO, "%s is %s\n", result.addrinfo->name, buf);
    }

    ares_freeaddrinfo(result.addrinfo);
}

void
reverse_dns(reactor_t * reactor, iou_ares_data_t * iou_ares_data, const char * addr) {
    struct sockaddr_storage sockaddr;
    socklen_t socklen = sockaddr_parse(&sockaddr, addr, 0);

    iou_ares_name_result_t result;
    iou_ares_nameinfo(iou_ares_data, (struct sockaddr *)&sockaddr, socklen, 0, &result);
    iou_ares_wait(&result.future);

    if (ARES_SUCCESS != result.status)
        return;

    iou_printf(reactor, STDOUT_FILENO, "%s is %s\n", addr, result.node ? result.node : "");

    free(result.node);
    free(result.service);
}

int
main(int argc, const char *argv[]) {
    reactor_t * reactor = reactor_get();

    TRY(ares_library_init, ARES_LIB_INIT_ALL);

    iou_ares_data_t iou_ares_data;
    struct ares_options options = {
        .flags = ARES_FLAG_STAYOPEN,
    };
    ares_channel_t * channel = iou_ares_get(reactor, &iou_ares_data, &options, 0
    | ARES_OPT_FLAGS
    );

    for (int i = 1 ; i < argc ; ++i) {
        struct sockaddr_storage sockaddr;
        if (sockaddr_parse(&sockaddr, argv[i], 0))
            reactor_fiber(reverse_dns, reactor, &iou_ares_data, (char*)argv[i]);
        else
            reactor_fiber(resolve_dns, reactor, &iou_ares_data, (char*)argv[i]);
    }

    reactor_run(reactor);

    iou_ares_put(&iou_ares_data);
    ares_library_cleanup();
    return 0;
}
