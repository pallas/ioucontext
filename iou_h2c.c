// SPDX-License-Identifier: MIT
#define _GNU_SOURCE

#include <ioucontext/ioucontext.h>

#include <assert.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <nghttp2/nghttp2.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <sys/poll.h>
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
    off_t fd_off;
    int pipe_in;
    int pipe_out;
    ssize_t pipe_bytes, pipe_max;
    stream_data_entry_t entry;
} stream_data_t;

typedef struct session_data_s {
    reactor_t *reactor;
    int fd;
    ssize_t fd_space;
    stream_data_list_t free_streams;
    stream_data_list_t inuse_streams;
    union {
        uint8_t flags;
        struct {
            uint8_t want_read:1;
            uint8_t need_poll_in:1;
            uint8_t want_write:1;
            uint8_t need_poll_out:1;
        };
    };
} session_data_t;

static stream_data_t *
stream_data_get(session_data_t *session_data) {
    if (LIST_EMPTY(&session_data->free_streams))
        return NULL;

    stream_data_t *stream_data = LIST_FIRST(&session_data->free_streams);
    LIST_REMOVE(stream_data, entry);

    *stream_data = (stream_data_t){ .fd = -1, .pipe_in = -1, .pipe_out = -1, };

    LIST_INSERT_HEAD(&session_data->inuse_streams, stream_data, entry);
    return stream_data;
}

static void
stream_data_put(session_data_t *session_data, stream_data_t *stream_data) {
    LIST_REMOVE(stream_data, entry);

    if (stream_data->fd >= 0)
        iou_close_fast(session_data->reactor, stream_data->fd);

    if (stream_data->pipe_in >= 0)
        iou_close_fast(session_data->reactor, stream_data->pipe_in);

    if (stream_data->pipe_out >= 0)
        iou_close_fast(session_data->reactor, stream_data->pipe_out);

    LIST_INSERT_HEAD(&session_data->free_streams, stream_data, entry);
}

nghttp2_option *option;
nghttp2_session_callbacks *callbacks;

static void
iou_rand_callback(uint8_t *dest, size_t destlen) {
    if (destlen != iou_getrandom(reactor_get(), dest, destlen))
        abort();
}

static nghttp2_ssize
iou_send_callback2(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data) {
    session_data_t *session_data = (session_data_t *)user_data;

    if (session_data->need_poll_out)
        return NGHTTP2_ERR_WOULDBLOCK;

    int result = RESTART(iou_send, session_data->reactor, session_data->fd, data, length, 0
    | (session_data->want_read ? MSG_DONTWAIT : MSG_WAITALL)
    | (nghttp2_session_get_outbound_queue_size(session) ? MSG_MORE : 0)
    );

    if (result == -EAGAIN || result == -EWOULDBLOCK) {
        session_data->need_poll_out = true;
        return NGHTTP2_ERR_WOULDBLOCK;
    } else if (result < 0) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    if (session_data->fd_space >= 0) {
        if (session_data->fd_space > length)
            session_data->fd_space -= length;
        else
            session_data->fd_space = 0;
    }

    return result;
}

static nghttp2_ssize
iou_recv_callback2(nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data) {
    session_data_t *session_data = (session_data_t *)user_data;
    if (session_data->need_poll_in)
        return NGHTTP2_ERR_WOULDBLOCK;
    if (!session_data->want_write)
        session_data->want_write = nghttp2_session_want_write(session);
    int result = RESTART(iou_recv, session_data->reactor, session_data->fd, buf, length, session_data->want_write ? MSG_DONTWAIT : 0);
    if ((result == -EAGAIN || result == -EWOULDBLOCK) || (result > 0 && result < length))
        session_data->need_poll_in = true;
    return (result == -EAGAIN || result == -EWOULDBLOCK) ? NGHTTP2_ERR_WOULDBLOCK
        : (result == 0 || result == -ECONNRESET) ? NGHTTP2_ERR_EOF
        : (result < 0) ? NGHTTP2_ERR_CALLBACK_FAILURE
        : result
        ;
}

static int
iou_on_begin_headers_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    session_data_t *session_data = (session_data_t *)user_data;

    stream_data_t *stream_data = stream_data_get(session_data);
    if (!stream_data) {
        nghttp2_submit_rst_stream(session, 0, frame->hd.stream_id, NGHTTP2_ENHANCE_YOUR_CALM);
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    stream_data->fd = iou_open_direct(session_data->reactor, words_file, O_RDONLY, O_CLOEXEC);

    if (stream_data->fd >= 0) {
        iou_fadvise(session_data->reactor, stream_data->fd, 0, 0, POSIX_FADV_SEQUENTIAL);

        int result = iou_pipe_direct(session_data->reactor, &stream_data->pipe_out, &stream_data->pipe_in, O_CLOEXEC | O_NONBLOCK);
        stream_data->pipe_max = result < 0 ? -1 : (1<<16); //fcntl(stream_data->pipe_in, F_GETPIPE_SZ);
    }

    nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, stream_data);
    return 0;
}

static int
iou_on_header_callback2(nghttp2_session *session, const nghttp2_frame *frame, nghttp2_rcbuf *name, nghttp2_rcbuf *value, uint8_t flags, void *user_data) {
    session_data_t *session_data = (session_data_t *)user_data;

    stream_data_t *stream_data = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (!stream_data)
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

    /* nghttp2_vec n = nghttp2_rcbuf_get_buf(name); */
    /* nghttp2_vec v = nghttp2_rcbuf_get_buf(value); */

    return 0;
}

static nghttp2_ssize
fd_read_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data) {
    session_data_t *session_data = (session_data_t *)user_data;
    stream_data_t *stream_data = (stream_data_t *)source->ptr;

    const ssize_t splice_threshold = 3<<12; /* 12kB */

    if (stream_data->fd < 0 && !stream_data->pipe_bytes)
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    if (stream_data->fd >= 0 && stream_data->pipe_in >= 0 && stream_data->pipe_bytes < stream_data->pipe_max/2) {
        ssize_t n = RESTART(iou_splice_offset, session_data->reactor, stream_data->fd, &stream_data->fd_off, stream_data->pipe_in, NULL, SSIZE_MAX, 0 | SPLICE_F_MOVE);
        if (n > 0) {
            stream_data->pipe_bytes += n;
        } else if (n == 0) {
            iou_close_fast(session_data->reactor, stream_data->fd);
            stream_data->fd = -1;
        } else if (n == -EAGAIN || n == -EWOULDBLOCK) {
            if (!stream_data->pipe_bytes)
                return NGHTTP2_ERR_PAUSE;
        } else {
            iou_close_fast(session_data->reactor, stream_data->pipe_in);
            stream_data->pipe_in = -1;
        }
    }

    if (stream_data->fd >= 0 && stream_data->pipe_in < 0 && !stream_data->pipe_bytes) {
        ssize_t n = RESTART(iou_pread, session_data->reactor, stream_data->fd, buf, length, stream_data->fd_off);
        if (n == -EAGAIN || n == -EWOULDBLOCK)
            return NGHTTP2_ERR_PAUSE;
        else if (n <= 0)
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

        stream_data->fd_off += n;

        if (n < length)
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;

        return n;
    } else if (stream_data->pipe_bytes >= length && length >= splice_threshold) {
        *data_flags |= NGHTTP2_DATA_FLAG_NO_COPY;
        return length;
    } else if (stream_data->pipe_bytes >= length) {
        ssize_t n = RESTART(iou_read, session_data->reactor, stream_data->pipe_out, buf, length);
        if (n == -EAGAIN || n == -EWOULDBLOCK)
            return NGHTTP2_ERR_PAUSE;
        else if (n <= 0)
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

        stream_data->pipe_bytes -= n;

        return n;
    } else if (stream_data->pipe_bytes >= stream_data->pipe_max/2) {
        *data_flags |= NGHTTP2_DATA_FLAG_NO_COPY;
        if (stream_data->fd < 0)
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return stream_data->pipe_bytes;
    } else if (stream_data->fd >= 0) {
        return NGHTTP2_ERR_PAUSE;
    } else if (stream_data->pipe_bytes >= splice_threshold) {
        *data_flags |= NGHTTP2_DATA_FLAG_NO_COPY;
        if (stream_data->fd < 0)
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return stream_data->pipe_bytes;
    } else if (stream_data->pipe_bytes) {
        ssize_t n = RESTART(iou_read, session_data->reactor, stream_data->pipe_out, buf, stream_data->pipe_bytes);
        if (n == -EAGAIN || n == -EWOULDBLOCK)
            return NGHTTP2_ERR_PAUSE;
        else if (n <= 0)
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

        stream_data->pipe_bytes -= n;
        if (stream_data->fd < 0 && !stream_data->pipe_bytes)
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;

        return n;
    } else {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }

    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
}

static int
iou_send_data_callback(nghttp2_session *session, nghttp2_frame *frame, const uint8_t *framehd, size_t length, nghttp2_data_source *source, void *user_data) {
    session_data_t *session_data = (session_data_t *)user_data;
    stream_data_t *stream_data = (stream_data_t *)source->ptr;

    enum { framehd_len = 9 };

    if (session_data->need_poll_out || stream_data->pipe_bytes < length)
        return NGHTTP2_ERR_WOULDBLOCK;

    const size_t total_len = framehd_len + length + frame->data.padlen;
    if (session_data->fd_space >= 0) {
        if (session_data->fd_space < total_len)
            session_data->fd_space = RESTART(iou_spaceout, session_data->reactor, session_data->fd);

        if (session_data->fd_space < total_len)
            return NGHTTP2_ERR_WOULDBLOCK;
    }

    bool have_pad = frame->data.padlen > 0;
    uint8_t buffer[framehd_len+1];
    size_t buffer_len = framehd_len+have_pad;
    if (have_pad) {
        memcpy(buffer, framehd, framehd_len);
        buffer[framehd_len] = frame->data.padlen - 1;
    }

    static const uint8_t pad[255] = {0};
    size_t pad_len = frame->data.padlen > 1 ? frame->data.padlen - 1 : 0;
    assert(pad_len <= sizeof(pad));

    ssize_t n = pad_len > 0
        ? iou_output(session_data->reactor, session_data->fd, NULL
            , iou_output_send(.buffer=have_pad ? buffer : framehd, .length=buffer_len)
            , iou_output_splice(.fd_in=stream_data->pipe_out, .length=length)
            , iou_output_send(.buffer=pad, .length=pad_len)
            )
        : iou_output(session_data->reactor, session_data->fd, NULL
            , iou_output_send(.buffer=have_pad ? buffer : framehd, .length=buffer_len)
            , iou_output_splice(.fd_in=stream_data->pipe_out, .length=length)
            )
        ;

    if (n == -EAGAIN || n == -EWOULDBLOCK) {
        session_data->need_poll_out = true;
        return NGHTTP2_ERR_WOULDBLOCK;
    } else if (n < 0) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    if (session_data->fd_space >= 0) {
        if (session_data->fd_space > total_len)
            session_data->fd_space -= total_len;
        else
            session_data->fd_space = 0;
    }

    stream_data->pipe_bytes -= length;

    return n != total_len ? NGHTTP2_ERR_CALLBACK_FAILURE : 0;
}

#define NV(NAME, VALUE) (nghttp2_nv){ \
    .name = (uint8_t *)(NAME), \
    .namelen = (__builtin_constant_p(NAME) ? (sizeof(NAME) - 1) : strlen(NAME)), \
    .value = (uint8_t *)(VALUE), \
    .valuelen = (__builtin_constant_p(VALUE) ? (sizeof(VALUE) - 1) : strlen(VALUE)), \
    .flags = NGHTTP2_NV_FLAG_NONE \
        | (__builtin_constant_p(NAME) ? NGHTTP2_NV_FLAG_NO_COPY_NAME : NGHTTP2_NV_FLAG_NONE) \
        | (__builtin_constant_p(VALUE) ? NGHTTP2_NV_FLAG_NO_COPY_VALUE : NGHTTP2_NV_FLAG_NONE) \
}

static int
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
            .source = { .ptr = stream_data, },
            .read_callback = fd_read_callback,
        };

        nghttp2_nv nvs[] = { NV(":status", "200"), };
        nghttp2_submit_response2(session, frame->hd.stream_id, nvs, sizeof(nvs)/sizeof(*nvs), &data_provider);
    }

    return 0;
}

static int
iou_on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data) {
    session_data_t *session_data = (session_data_t *)user_data;

    stream_data_t *stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
    if (stream_data) {
        nghttp2_session_set_stream_user_data(session, stream_id, NULL);
        stream_data_put(session_data, stream_data);
    }

    return 0;
}

static int
iou_error_callback2(nghttp2_session *session, int lib_error_code, const char *msg, size_t len, void *user_data) {
    session_data_t *session_data = (session_data_t *)user_data;
    iou_printf(session_data->reactor, STDERR_FILENO, "%p session error %d %.*s\n", session, lib_error_code, (int)len, msg);
    return 0;
}

static int
session_io(nghttp2_session *session, session_data_t * session_data) {
    int result;
    session_data->want_read = nghttp2_session_want_read(session);
    session_data->want_write = nghttp2_session_want_write(session);
    while (session_data->want_read || session_data->want_write) {
        if (session_data->want_read && !session_data->need_poll_in) {
            /* fastpath */
        } else if (session_data->want_write && !session_data->need_poll_out) {
            /* fastpath */
        } else if (session_data->need_poll_in || session_data->need_poll_out) {
            assert(!session_data->want_read || session_data->need_poll_in);
            assert(!session_data->want_write || session_data->need_poll_out);

            static const unsigned in_mask = POLLIN | POLLPRI | POLLRDHUP | POLLHUP;
            static const unsigned out_mask = POLLOUT | POLLHUP;
            const unsigned mask = POLLERR
                | (session_data->need_poll_in ? in_mask : 0)
                | (session_data->need_poll_out ? out_mask : 0)
                ;
            unsigned events = iou_poll(session_data->reactor, session_data->fd, mask, timespec_block);

            if (events & (POLLERR))
                return NGHTTP2_ERR_SESSION_CLOSING;

            if (events & (POLLIN | POLLPRI | POLLRDHUP | POLLHUP))
                session_data->need_poll_in = false;

            if (events & (POLLOUT | POLLHUP))
                session_data->need_poll_out = false;
        }

        if (session_data->want_read && !session_data->need_poll_in) {
            if ((result = nghttp2_session_recv(session)))
                return result;

            session_data->want_read = nghttp2_session_want_read(session);
            if (!session_data->want_write)
                session_data->want_write = nghttp2_session_want_write(session);
        }

        if (session_data->want_write && !session_data->need_poll_out) {
            if ((result = nghttp2_session_send(session)))
                return result;

            session_data->want_read = nghttp2_session_want_read(session);
            session_data->want_write = nghttp2_session_want_write(session);
        }
    }

    return 0;
}

void
process(reactor_t * reactor, session_data_t * session_data, nghttp2_settings_entry * settings, size_t settings_n) {
    nghttp2_session *session = NULL;
    nghttp2_session_server_new3(&session, callbacks, session_data, NULL, NULL);
    iou_printf(reactor, STDERR_FILENO, "%p session begin\n", session);

    int result = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, settings, settings_n);
    if (!result)
        result = session_io(session, session_data);

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

    while ((session_data.fd = iou_accept_direct(reactor, accept_fd, NULL, 0, SOCK_CLOEXEC)) >= 0) {

        const struct timespec when = reify_timespec(timespec_ms(5));
        if (iou_yield(reactor) && timespec_past(dereify_timespec(when))) {
            const static struct linger linger_zero = { .l_onoff = 1, .l_linger = 0, };
            TRY(iou_setsockopt, reactor, session_data.fd, SOL_SOCKET, SO_LINGER, &linger_zero, sizeof linger_zero);
        } else {
            TRY(iou_setsockopt_int, reactor, session_data.fd, IPPROTO_TCP, TCP_NODELAY, 1);
            TRY(iou_setsockopt_int, reactor, session_data.fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, 1<<15);
            process(reactor, &session_data, settings, sizeof(settings)/sizeof(*settings));
        }
        session_data.flags = 0;
        session_data.fd_space = 0;

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

    int accept_fd = iou_fd_register(reactor, info->accept_fd);
    for (unsigned i = 0 ; i < 64 ; ++i)
        reactor_fiber(fiber, reactor, accept_fd);

    reactor_run(reactor);

    if (info->accept_fd != accept_fd)
        iou_close_fast(reactor, accept_fd);

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
    nghttp2_session_callbacks_set_rand_callback(callbacks, iou_rand_callback);
    nghttp2_session_callbacks_set_send_callback2(callbacks, iou_send_callback2);
    nghttp2_session_callbacks_set_send_data_callback(callbacks, iou_send_data_callback);
    nghttp2_session_callbacks_set_recv_callback2(callbacks, iou_recv_callback2);

    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, iou_on_begin_headers_callback);
    nghttp2_session_callbacks_set_on_header_callback2(callbacks, iou_on_header_callback2);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, iou_on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, iou_on_stream_close_callback);
    nghttp2_session_callbacks_set_error_callback2(callbacks, iou_error_callback2);


    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGINT);
    TRY(sigprocmask, SIG_BLOCK, &mask, NULL);

    for (int i = 0 ; i < cpus ; ++i)
        thrd_create(&thread_infos[i].thrd, thread, &thread_infos[i]);

    int signal_fd = TRY(signalfd, -1, &mask, 0);
    struct signalfd_siginfo si;
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
