// SPDX-License-Identifier: MIT
#define _GNU_SOURCE

#include <ioucontext/ioucontext.h>

#include <assert.h>
#include <fcntl.h>
#include <nghttp2/nghttp2.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/signalfd.h>
#include <sys/sysinfo.h>
#include <threads.h>

const static char words_file[] = "/usr/share/dict/words";

typedef struct stream_data_s stream_data_t;
typedef struct session_data_s session_data_t;

typedef LIST_HEAD(stream_data_list_s, stream_data_s) stream_data_list_t;
typedef LIST_ENTRY(stream_data_s) stream_data_entry_t;

typedef struct stream_data_s {
    int fd;
    stream_data_entry_t entry;
} stream_data_t;

typedef struct session_data_s {
    reactor_t *reactor;
    int fd;
    stream_data_list_t free_streams;
    stream_data_list_t inuse_streams;
} session_data_t;

static stream_data_t *
stream_data_get(session_data_t *session_data) {
    if (LIST_EMPTY(&session_data->free_streams))
        return NULL;

    stream_data_t *stream_data = LIST_FIRST(&session_data->free_streams);
    LIST_REMOVE(stream_data, entry);

    *stream_data = (stream_data_t){ .fd = -1, };

    LIST_INSERT_HEAD(&session_data->inuse_streams, stream_data, entry);
    return stream_data;
}

static void
stream_data_put(session_data_t *session_data, stream_data_t *stream_data) {
    LIST_REMOVE(stream_data, entry);

    if (stream_data->fd >= 0)
        iou_close_fast(session_data->reactor, stream_data->fd);

    LIST_INSERT_HEAD(&session_data->free_streams, stream_data, entry);
}

nghttp2_option *option;
nghttp2_session_callbacks *callbacks;

nghttp2_ssize
iou_send_callback2(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data) {
    session_data_t *session_data = (session_data_t *)user_data;
    int result = iou_send(session_data->reactor, session_data->fd, data, length, MSG_DONTWAIT);
    return (result == -EAGAIN || result == -EWOULDBLOCK || result == -EINTR) ? NGHTTP2_ERR_WOULDBLOCK
        : (result < 0) ? NGHTTP2_ERR_CALLBACK_FAILURE
        : result
        ;
}

nghttp2_ssize
iou_recv_callback2(nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data) {
    session_data_t *session_data = (session_data_t *)user_data;
    int result = iou_recv(session_data->reactor, session_data->fd, buf, length, MSG_DONTWAIT);
    return (result == -EAGAIN || result == -EWOULDBLOCK || result == -EINTR) ? NGHTTP2_ERR_WOULDBLOCK
        : (result == 0 || result == -ECONNRESET) ? NGHTTP2_ERR_EOF
        : (result < 0) ? NGHTTP2_ERR_CALLBACK_FAILURE
        : result
        ;
}

int
iou_on_begin_headers_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    session_data_t *session_data = (session_data_t *)user_data;

    stream_data_t *stream_data = stream_data_get(session_data);
    if (!stream_data) {
        nghttp2_submit_rst_stream(session, 0, frame->hd.stream_id, NGHTTP2_ENHANCE_YOUR_CALM);
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    stream_data->fd = iou_open(session_data->reactor, words_file, O_RDONLY, 0);

    if (stream_data->fd >= 0)
        iou_fadvise(session_data->reactor, stream_data->fd, 0, 0, POSIX_FADV_SEQUENTIAL | POSIX_FADV_NOREUSE);

    nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, stream_data);
    return 0;
}

int
iou_on_header_callback2(nghttp2_session *session, const nghttp2_frame *frame, nghttp2_rcbuf *name, nghttp2_rcbuf *value, uint8_t flags, void *user_data) {
    session_data_t *session_data = (session_data_t *)user_data;

    stream_data_t *stream_data = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (!stream_data)
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

    /* nghttp2_vec n = nghttp2_rcbuf_get_buf(name); */
    /* nghttp2_vec v = nghttp2_rcbuf_get_buf(value); */

    return 0;
}

static
nghttp2_ssize
fd_read_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data) {
    session_data_t *session_data = (session_data_t *)user_data;

    int n = iou_read(session_data->reactor, source->fd, buf, length);
    if (n < 0)
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

    if (!n)
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;

    return n;
}

#define NV(NAME, VALUE) (nghttp2_nv){ \
    .name = (uint8_t *)(NAME), \
    .namelen = strlen(NAME), \
    .value = (uint8_t *)(VALUE), \
    .valuelen = strlen(VALUE), \
    .flags = NGHTTP2_NV_FLAG_NONE, \
}

int
iou_on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    session_data_t *session_data = (session_data_t *)user_data;

    bool last = frame->hd.flags & NGHTTP2_FLAG_END_STREAM;
    bool data = frame->hd.type == NGHTTP2_DATA;
    bool headers = frame->hd.type == NGHTTP2_HEADERS;

    if (!frame->hd.stream_id || !last)
        return 0;

    if (!headers && !data)
        return 0;

    stream_data_t *stream_data = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (!stream_data) {
        nghttp2_nv nvs[] = { NV(":status", "503") };
        nghttp2_submit_response2(session, frame->hd.stream_id, nvs, sizeof(nvs)/sizeof(*nvs), NULL);
    } else if (stream_data->fd < 0) {
        nghttp2_nv nvs[] = { NV(":status", "404") };
        nghttp2_submit_response2(session, frame->hd.stream_id, nvs, sizeof(nvs)/sizeof(*nvs), NULL);
    } else {
        nghttp2_data_provider2 data_provider = {
            .source = { .fd = stream_data->fd, },
            .read_callback = fd_read_callback,
        };

        nghttp2_nv nvs[] = { NV(":status", "200"), };
        nghttp2_submit_response2(session, frame->hd.stream_id, nvs, sizeof(nvs)/sizeof(*nvs), &data_provider);
    }

    return 0;
}

int
iou_on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data) {
    session_data_t *session_data = (session_data_t *)user_data;

    stream_data_t *stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
    if (stream_data) {
        nghttp2_session_set_stream_user_data(session, stream_id, NULL);
        stream_data_put(session_data, stream_data);
    }

    return 0;
}

void
process(reactor_t * reactor, session_data_t * session_data, nghttp2_settings_entry * settings, size_t settings_n) {
    nghttp2_session *session = NULL;
    nghttp2_session_server_new3(&session, callbacks, session_data, NULL, NULL);
    iou_printf(reactor, STDERR_FILENO, "%p session begin\n", session);

    int result;
    if (!(result = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, settings, settings_n)))
    while (nghttp2_session_want_read(session) || nghttp2_session_want_write(session)) {
        if (nghttp2_session_want_read(session) && (result = nghttp2_session_recv(session))) break;
        if (nghttp2_session_want_write(session) && (result = nghttp2_session_send(session))) break;
    }

    while (nghttp2_session_want_write(session) && !(result = nghttp2_session_send(session))) { }

    iou_printf(reactor, STDERR_FILENO, "%p session end %s\n", session, nghttp2_strerror(result));
    nghttp2_session_del(session);
}

void
fiber(reactor_t * reactor, int accept_fd) {
    session_data_t session_data = {
        .reactor = reactor,
        .free_streams = LIST_HEAD_INITIALIZER(free_streams),
        .inuse_streams = LIST_HEAD_INITIALIZER(inuse_streams),
    };

    const size_t streams_n = 32;
    stream_data_t stream_datas[streams_n] = { };
    for (size_t i = 0 ; i < streams_n ; ++i)
        LIST_INSERT_HEAD(&session_data.free_streams, &stream_datas[i], entry);

    nghttp2_settings_entry settings[] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, streams_n },
        { NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES, 1 },
    };

    while ((session_data.fd = iou_accept(reactor, accept_fd, NULL, 0, SOCK_NONBLOCK | SOCK_CLOEXEC)) >= 0) {
        process(reactor, &session_data, settings, sizeof(settings)/sizeof(*settings));
        while (!LIST_EMPTY(&session_data.inuse_streams))
            stream_data_put(&session_data, LIST_FIRST(&session_data.inuse_streams));
        iou_close_fast(reactor, session_data.fd);
    }
}

typedef struct {
    thrd_t thrd;
    int cpu;
    int accept_fd;
} thread_info_t;

int
thread(void *context) {
    thread_info_t *info = (thread_info_t *)context;

    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(info->cpu, &cpu_set);
    TRY(sched_setaffinity, 0, sizeof(cpu_set_t), &cpu_set);

    reactor_t *reactor = reactor_get();

    for (unsigned i = 0 ; i < 64 ; ++i)
        reactor_fiber(fiber, reactor, info->accept_fd);

    reactor_run(reactor);
    return 0;
}

int
server_fd(reactor_t * reactor, const struct sockaddr *addr, socklen_t addrlen) {
    int fd = TRY(iou_socket, reactor, addr->sa_family, SOCK_STREAM | SOCK_CLOEXEC, PF_UNSPEC);
    TRY(iou_setsockopt_int, reactor, fd, SOL_SOCKET, SO_REUSEADDR, true);
    TRY(iou_setsockopt_int, reactor, fd, SOL_SOCKET, SO_REUSEPORT, true);
    TRY(iou_bind, reactor, fd, addr, addrlen);
    TRY(iou_listen, reactor, fd, 4);
    return fd;
}

int
main(int argc, char *argv[]) {
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    TRY(sched_setaffinity, 0, sizeof(cpu_set_t), &cpu_set);

    TRY(signal, SIGPIPE, SIG_IGN);

    reactor_t * reactor = reactor_get();

    struct sockaddr_storage ss;
    if (!sockaddr_parse(&ss, "::1", 8000))
        abort();

    unsigned cpus = TRY(get_nprocs_conf);
    thread_info_t thread_infos[cpus];
    for (int i = 0 ; i < cpus ; ++i) thread_infos[i] = (thread_info_t){
        .cpu = i,
        .accept_fd = TRY(server_fd, reactor, (const struct sockaddr *)&ss, sizeof ss),
    };

    TRY(nghttp2_option_new, &option);
    nghttp2_option_set_no_http_messaging(option, true);

    TRY(nghttp2_session_callbacks_new, &callbacks);
    nghttp2_session_callbacks_set_send_callback2(callbacks, iou_send_callback2);
    nghttp2_session_callbacks_set_recv_callback2(callbacks, iou_recv_callback2);

    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, iou_on_begin_headers_callback);
    nghttp2_session_callbacks_set_on_header_callback2(callbacks, iou_on_header_callback2);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, iou_on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, iou_on_stream_close_callback);


    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGINT);
    TRY(sigprocmask, SIG_BLOCK, &mask, NULL);

    for (int i = 0 ; i < cpus ; ++i)
        thrd_create(&thread_infos[i].thrd, thread, &thread_infos[i]);

    int signal_fd = TRY(signalfd, -1, &mask, 0);
    struct signalfd_siginfo si;
    explicit_bzero(&si, sizeof si);
    do {
        if (TRY(iou_read, reactor, signal_fd, &si, sizeof si) < sizeof si)
            abort();
    } while (!sigismember(&mask, si.ssi_signo));

    TRY(sigprocmask, SIG_UNBLOCK, &mask, NULL);
    iou_close_fast(reactor, signal_fd);

    for (int i = 0 ; i < cpus ; ++i)
        iou_shutdown(reactor, thread_infos[i].accept_fd);

    for (int i = 0 ; i < cpus ; ++i)
        thrd_join(thread_infos[i].thrd, NULL);

    nghttp2_session_callbacks_del(callbacks);
    nghttp2_option_del(option);

    for (int i = 0 ; i < cpus ; ++i)
        iou_close_fast(reactor, thread_infos[i].accept_fd);

    thrd_exit(0);
    return 0;
}

//
