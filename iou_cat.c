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

static const uint64_t efd_eof = UINT64_MAX - 1;

int
source(reactor_t * reactor, int from, int to, int efd) {
    int pipe_buf_size = min(max_pipe(from), max_pipe(to));

    if (!isatty(from))
        io_fadvise(reactor, from, 0, 0, POSIX_FADV_SEQUENTIAL | POSIX_FADV_WILLNEED);

    int64_t bytes; // must be signed
    while ((bytes = io_splice(reactor, from, to, pipe_buf_size)) > 0)
        TRY(io_write, reactor, efd, &bytes, sizeof bytes);

    return bytes;
}

void
drain(reactor_t * reactor, int from, int to, int efd) {
    int pipe_buf_size = min(max_pipe(from), max_pipe(to));

    if (isatty(to))
        fcntl(to, F_SETFL, ~O_APPEND & fcntl(to, F_GETFL));

    uint64_t bytes;
    while (io_read(reactor, efd, &bytes, sizeof bytes) > 0 && bytes != efd_eof) {
        while (bytes > 0) {
            int n = io_splice(reactor, from, to, bytes);
            if (n <= 0) {
                TRY(io_close, reactor, from);
                io_read(reactor, efd, &bytes, sizeof bytes);
                return;
            }
            bytes -= n;
        }
    }
}

void
cat(reactor_t * reactor, int argc, const char *argv[]) {
    int pipes[2];
    TRY(pipe, pipes);

    int efd = TRY(eventfd, 0, 0);

    reactor_fiber(drain, reactor, pipes[0], STDOUT_FILENO, efd);

    if (argc <= 1) {
        source(reactor, STDIN_FILENO, pipes[1], efd);
    } else for (int i = 1 ; i < argc ; ++i) {
        if (!strcmp("-", argv[i])) {
            if (source(reactor, STDIN_FILENO, pipes[1], efd))
                break;
        } else {
            int fd = TRY(io_open, reactor, argv[i], O_RDONLY, 0);
            if (source(reactor, fd, pipes[1], efd))
                break;
            TRY(io_close, reactor, fd);
        }
    }

    uint64_t bytes = efd_eof;
    TRY(io_write, reactor, efd, &bytes, sizeof bytes);
}

int
main(int argc, char *argv[]) {
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
