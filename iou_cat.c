// SPDX-License-Identifier: MIT
#define _GNU_SOURCE

#include <ioucontext/ioucontext.h>

#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <sys/eventfd.h>
#include <threads.h>

static inline int min(int l, int r) { return l < r ? l : r; }
static inline int max(int l, int r) { return l > r ? l : r; }

int
max_pipe(int fd) {
    int size = fcntl(fd, F_GETPIPE_SZ);
    if (size < PIPE_BUF)
        return PIPE_BUF;

    while ((size = fcntl(fd, F_SETPIPE_SZ, size << 1)) > 0) { }

    return fcntl(fd, F_GETPIPE_SZ);
}

enum { efd_eof = UINT64_MAX - 1 };

int
source(reactor_t * reactor, int from, int to, int efd) {
    int pipe_buf_size = min(max_pipe(from), max_pipe(to));

    if (!isatty(from))
        iou_fadvise_fast(reactor, from, 0, 0, POSIX_FADV_SEQUENTIAL | POSIX_FADV_WILLNEED);

    int64_t bytes; // must be signed
    while ((bytes = iou_splice(reactor, from, to, pipe_buf_size)) > 0)
        TRY(iou_write, reactor, efd, &bytes, sizeof bytes);

    return bytes;
}

void
drain(reactor_t * reactor, int from, int to, int efd) {
    int pipe_buf_size = min(max_pipe(from), max_pipe(to));

    if (isatty(to))
        fcntl(to, F_SETFL, ~O_APPEND & fcntl(to, F_GETFL));

    uint64_t bytes = 0;
    while (iou_read(reactor, efd, &bytes, sizeof bytes) == sizeof bytes && bytes != efd_eof) {
        while (bytes > 0) {
            int n = iou_splice(reactor, from, to, bytes);
            if (n <= 0) {
                TRY(iou_close, reactor, from);
                iou_read(reactor, efd, &bytes, sizeof bytes);
                return;
            }
            bytes -= n;
        }
    }
}

void
cat(reactor_t * reactor, int argc, const char *argv[]) {
    int pipe_out, pipe_in;
    TRY(iou_pipe, reactor, &pipe_out, &pipe_in, O_CLOEXEC);

    int efd = TRY(eventfd, 0, 0);

    reactor_fiber(drain, reactor, pipe_out, STDOUT_FILENO, efd);

    if (argc <= 1) {
        source(reactor, STDIN_FILENO, pipe_in, efd);
    } else for (int i = 1 ; i < argc ; ++i) {
        if (!strcmp("-", argv[i])) {
            if (source(reactor, STDIN_FILENO, pipe_in, efd))
                break;
        } else {
            int fd = TRY(iou_open_direct, reactor, argv[i], O_RDONLY, 0);
            if (source(reactor, fd, pipe_in, efd))
                break;
            TRY(iou_close, reactor, fd);
        }
    }

    uint64_t bytes = efd_eof;
    TRY(iou_write, reactor, efd, &bytes, sizeof bytes);
}

int
main(int argc, const char *argv[]) {
    cpu_set_t cpu_set;
    CPU_ZERO_S(sizeof(cpu_set_t), &cpu_set);
    CPU_SET_S(0, sizeof(cpu_set_t), &cpu_set);
    TRY(sched_setaffinity, 0, sizeof(cpu_set_t), &cpu_set);

    reactor_t * reactor = reactor_get();

    reactor_fiber(cat, reactor, argc, argv);
    reactor_run(reactor);

    thrd_exit(0);
    return 0;
}

//
