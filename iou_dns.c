// SPDX-License-Identifier: MIT
#define _GNU_SOURCE

#include <ioucontext/ioucontext.h>
#include <ioucontext/iou-cares.h>

#include <ares.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

void
forward_dns(reactor_t * reactor, iou_ares_data_t * iou_ares_data, const char * name) {
    iou_ares_addr_result_t result;
    const struct ares_addrinfo_hints hints = {
        .ai_flags = ARES_AI_NOSORT,
    };
    iou_ares_addrinfo(iou_ares_data, name, NULL, &hints, &result);
    iou_ares_wait(&result.future);

    if (ARES_SUCCESS != result.status) {
        iou_printf(reactor, STDERR_FILENO, "%s: %s\n", name, ares_strerror(result.status));
        return;
    }

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

    if (ARES_SUCCESS != result.status) {
        iou_printf(reactor, STDERR_FILENO, "%s: %s\n", addr, ares_strerror(result.status));
        return;
    }

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
dns_worker(reactor_t * reactor, iou_ares_data_t * iou_ares_data, iou_queue_t * queue) {
    char * name;
    while (name = (char *)iou_queue_dequeue(reactor, queue)) {
        resolve_dns(reactor, iou_ares_data, name);
        free(name);
    }
    iou_queue_enqueue(reactor, queue, 0);
}

int
main(int argc, const char *argv[]) {
    reactor_t * reactor = reactor_get();

    TRY(ares_library_init, ARES_LIB_INIT_ALL);

    iou_ares_data_t iou_ares_data;
    struct ares_options options = {
        .flags = ARES_FLAG_STAYOPEN | ARES_FLAG_EDNS | ARES_FLAG_DNS0x20,
        .qcache_max_ttl = 5,
    };
    ares_channel_t * channel = iou_ares_get(reactor, &iou_ares_data, &options, 0
    | ARES_OPT_FLAGS
    | ARES_OPT_ROTATE
    | ARES_OPT_QUERY_CACHE
    );

    if (argc <= 1) {
        iou_queue_t queue;
        iou_queue(&queue);

        for (int i = 0 ; i < 256 ; ++i)
            reactor_fiber(dns_worker, reactor, &iou_ares_data, &queue);

        FILE * f = iou_fdopen(reactor, STDIN_FILENO, "r");
        if (!f)
            abort();

        ssize_t length = 0;
        char *buffer = NULL;
        while (-1 != (length = getdelim(&buffer, &length, '\n', f))) {
            char *token;
            char *cursor = buffer;
            while (token = strsep(&cursor, " \t\n")) {
                if (*token)
                if (token = strdup(token))
                    iou_queue_enqueue(reactor, &queue, (uintptr_t)token);
            }
        }

        fclose(f);
        free(buffer);
        iou_queue_enqueue(reactor, &queue, 0);
    } else for (int i = 1 ; i < argc ; ++i) {
        reactor_fiber(resolve_dns, reactor, &iou_ares_data, argv[i]);
    }

    reactor_run(reactor);

    iou_ares_put(&iou_ares_data);
    ares_library_cleanup();
    return 0;
}
