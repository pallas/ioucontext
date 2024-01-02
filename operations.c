// SPDX-License-Identifier: MIT
#define _GNU_SOURCE

#include "operations.h"

#include "macros.h"
#include "reactor-internal.h"

#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <netinet/in.h>

int
iou_accept(reactor_t * reactor, int fd, struct sockaddr *addr, socklen_t *addrlen) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_accept(sqe, fd, addr, addrlen, 0);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

void
iou_barrier(reactor_t * reactor) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_nop(sqe);
    io_uring_sqe_set_flags(sqe, IOSQE_IO_DRAIN);
    reactor_future_fake(reactor, sqe);
}

void
iou_cancel_fd_all(reactor_t * reactor, int fd) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_cancel_fd(sqe, fd, IORING_ASYNC_CANCEL_ALL);
    reactor_future_fake(reactor, sqe);
}

void
iou_cancel_fd_any(reactor_t * reactor, int fd) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_cancel_fd(sqe, fd, 0);
    reactor_future_fake(reactor, sqe);
}

int
iou_close(reactor_t * reactor, int fd) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_close(sqe, fd);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_connect(reactor_t * reactor, int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_connect(sqe, sockfd, addr, addrlen);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_exchange(reactor_t * reactor, const char *oldpath, const char *newpath) {
    return iou_exchangeat(reactor, AT_FDCWD, oldpath, newpath);
}

int
iou_exchangeat(reactor_t * reactor, int dirfd, const char *oldpath, const char *newpath) {
    return iou_renameat(reactor, dirfd, oldpath, dirfd, newpath, RENAME_EXCHANGE);
}

int
iou_fadvise(reactor_t * reactor, int fd, off_t offset, off_t len, int advice) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_fadvise(sqe, fd, offset, len, advice);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_fallocate(reactor_t * reactor, int fd, int mode, off_t offset, off_t len) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_fallocate(sqe, fd, mode, offset, len);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_fdatasync(reactor_t * reactor, int fd) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_fsync(sqe, fd, IORING_FSYNC_DATASYNC);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_fgetxattr(reactor_t * reactor, int fd, const char *name, void *value, size_t size) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_fgetxattr(sqe, fd, name, value, size);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

void
iou_flush(reactor_t * reactor) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_nop(sqe);
    io_uring_sqe_set_flags(sqe, IOSQE_IO_DRAIN);
    reactor_promise(reactor, sqe);
}

int
iou_fsetxattr(reactor_t * reactor, int fd, const char *name, const void *value, size_t size, int flags) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_fsetxattr(sqe, fd, name, value, size, flags);
    reactor_promise(reactor, sqe);

     return reactor->result;
}

int
iou_fsync(reactor_t * reactor, int fd) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_fsync(sqe, fd, 0);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_getxattr(reactor_t * reactor, const char *path, const char *name, void *value, size_t size) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_getxattr(sqe, name, value, path, size);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_link(reactor_t * reactor, const char *oldpath, const char *newpath) {
    return iou_linkat(reactor, AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
}

int iou_linkat(reactor_t * reactor, int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
    assert(reactor);

    if (!oldpath || !*oldpath)
        flags |= AT_EMPTY_PATH;

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_linkat(sqe, olddirfd, oldpath, newdirfd, newpath, flags);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_madvise(reactor_t * reactor, void *addr, size_t len, int advice) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_madvise(sqe, addr, len, advice);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_mkdir(reactor_t * reactor, const char *pathname, mode_t mode) {
    return iou_mkdirat(reactor, AT_FDCWD, pathname, mode);
}

int
iou_mkdirat(reactor_t * reactor, int dirfd, const char *pathname, mode_t mode) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_mkdirat(sqe, dirfd, pathname, mode);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_open(reactor_t * reactor, const char *pathname, int flags, mode_t mode) {
    return iou_openat(reactor, AT_FDCWD, pathname, flags, mode);
}

int
iou_openat(reactor_t * reactor, int dirfd, const char *pathname, int flags, mode_t mode) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_openat(sqe, dirfd, pathname, flags, mode);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

static bool
iou_poll_mask(reactor_t * reactor, int fd, unsigned mask, const struct timespec delta) {
    assert(reactor);

    if (!timespec_past(normalize_timespec(delta))) {
        struct timespec when = reify_timespec(delta);
        reactor_reserve_sqes(reactor, 2);

        struct io_uring_sqe * sqe = reactor_sqe(reactor);
        io_uring_prep_poll_add(sqe, fd, mask);
        reactor_promise_impatient(reactor, sqe, when);
    } else {
        struct io_uring_sqe * sqe = reactor_sqe(reactor);
        io_uring_prep_poll_add(sqe, fd, mask);
        reactor_promise(reactor, sqe);
    }

    return reactor->result > 0 && !!(reactor->result & mask);
}

bool iou_poll_hup(reactor_t * reactor, int fd, const struct timespec delta) { return iou_poll_mask(reactor, fd, POLLRDHUP, delta); }
bool iou_poll_in(reactor_t * reactor, int fd, const struct timespec delta) { return iou_poll_mask(reactor, fd, POLLIN, delta); }
bool iou_poll_out(reactor_t * reactor, int fd, const struct timespec delta) { return iou_poll_mask(reactor, fd, POLLOUT, delta); }

ssize_t
iou_pread(reactor_t * reactor, int fildes, void *buf, size_t nbytes, off_t offset) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_read(sqe, fildes, buf, nbytes, offset);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_printf(reactor_t * reactor, int fd, const char *format, ...) {
    int result;
    va_list args;
    va_start(args, format);
    result = iou_vprintf(reactor, fd, format, args);
    va_end(args);
    return result;
}

ssize_t
iou_pwrite(reactor_t * reactor, int fildes, const void *buf, size_t nbytes, off_t offset) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_write(sqe, fildes, buf, nbytes, offset);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

ssize_t
iou_read(reactor_t * reactor, int fildes, void *buf, size_t nbytes) {
    return iou_pread(reactor, fildes, buf, nbytes, -1);
}

ssize_t
iou_recv(reactor_t * reactor, int socket, void *buffer, size_t length, int flags) {
    return iou_recvfrom(reactor, socket, buffer, length, flags, NULL, 0);
}

ssize_t
iou_recvfrom(reactor_t * reactor, int socket, void *buffer, size_t length, int flags, struct sockaddr *address, socklen_t address_len) {
    assert(reactor);

    struct iovec iov = {
        .iov_base = buffer,
        .iov_len = length
    };

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_name = address,
        .msg_namelen = address_len,
    };

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_recvmsg(sqe, socket, &msg, flags);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_rename(reactor_t * reactor, const char *oldpath, const char *newpath) {
    return iou_renameat(reactor, AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
}

int
iou_rename_noreplace(reactor_t * reactor, const char *oldpath, const char *newpath) {
    return iou_renameat(reactor, AT_FDCWD, oldpath, AT_FDCWD, newpath, RENAME_NOREPLACE);
}

int
iou_renameat(reactor_t * reactor, int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_renameat(sqe, olddirfd, oldpath, newdirfd, newpath, flags);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_rmdir(reactor_t * reactor, const char *pathname) {
    return iou_rmdirat(reactor, AT_FDCWD, pathname);
}

int
iou_rmdirat(reactor_t * reactor, int dirfd, const char *pathname) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_unlinkat(sqe, dirfd, pathname, AT_REMOVEDIR);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

ssize_t
iou_send(reactor_t * reactor, int socket, const void *buffer, size_t length, int flags) {
    return iou_sendto(reactor, socket, buffer, length, flags, NULL, 0);
}

ssize_t
iou_sendto(reactor_t * reactor, int socket, const void *message, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t dest_len) {
    assert(reactor);

    struct iovec iov = {
        .iov_base = (void*)message,
        .iov_len = length
    };

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_name = (void*)dest_addr,
        .msg_namelen = dest_len,
    };

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_sendmsg(sqe, socket, &msg, flags);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_setxattr(reactor_t * reactor, const char *path, const char *name, const void *value, size_t size, int flags) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_setxattr(sqe, name, value, path, size, flags);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_shutdown(reactor_t * reactor, int sockfd) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_shutdown(sqe, sockfd, SHUT_RDWR);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_shutdown_read(reactor_t * reactor, int sockfd) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_shutdown(sqe, sockfd, SHUT_RD);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_shutdown_write(reactor_t * reactor, int sockfd) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_shutdown(sqe, sockfd, SHUT_WR);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

struct timespec
iou_sleep(reactor_t * reactor, const struct timespec delta) {
    assert(reactor);

    struct timespec now;
    TRY(clock_gettime, CLOCK_BOOTTIME, &now);
    const struct timespec when = normalize_timespec((struct timespec){
        .tv_sec = now.tv_sec + delta.tv_sec,
        .tv_nsec = now.tv_nsec + delta.tv_nsec,
    });

    if (iou_sleep_absolute(reactor, when))
        return (struct timespec){ .tv_sec = 0, .tv_nsec = 0 };

    TRY(clock_gettime, CLOCK_BOOTTIME, &now);
    const struct timespec remaining = normalize_timespec((struct timespec){
        .tv_sec = when.tv_sec - now.tv_sec,
        .tv_nsec = when.tv_nsec - now.tv_nsec,
    });

    if (remaining.tv_sec < 0)
        return (struct timespec){ .tv_sec = 0, .tv_nsec = 0 };

    return remaining;
}

bool
iou_sleep_absolute(reactor_t * reactor, const struct timespec when) {
    assert(reactor);

    const struct timespec ts = normalize_timespec(when);
    struct __kernel_timespec kts = {
        .tv_sec = ts.tv_sec,
        .tv_nsec = ts.tv_nsec,
    };

    while (true) {
        struct io_uring_sqe * sqe = reactor_sqe(reactor);
        io_uring_prep_timeout(sqe, &kts, 0, 0
            | IORING_TIMEOUT_ABS
            | IORING_TIMEOUT_BOOTTIME
        );
        reactor_promise(reactor, sqe);

        switch (reactor->result) {
        case 0: continue;
        case -ETIME: return true;
        default: return false;
        }
    }
}

int
iou_socket(reactor_t * reactor, int domain, int type, int protocol) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_socket(sqe, domain, type, protocol, 0);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

ssize_t
iou_splice(reactor_t * reactor, int fd_in, int fd_out, size_t len) {
    return iou_splice_offset(reactor, fd_in, NULL, fd_out, NULL, len);
}

ssize_t
iou_splice_all(reactor_t * reactor, int fd_in, int fd_out, size_t len) {
    ssize_t bytes = 0;

    while (bytes < len) {
        ssize_t n = iou_splice(reactor, fd_in, fd_out, len - bytes);
        if (n < 0)
            return n;
        bytes += n;
    }

    return bytes;
}

ssize_t
iou_splice_offset(reactor_t * reactor, int fd_in, off_t *off_in, int fd_out, off_t *off_out, size_t len) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_splice(sqe, fd_in, off_in ? *off_in : -1, fd_out, off_out ? *off_out : -1, len, SPLICE_F_MORE | SPLICE_F_MOVE);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_statx(reactor_t * reactor, const char *pathname, struct statx *statxbuf) {
    return iou_statxat(reactor, AT_FDCWD, pathname, 0, STATX_BASIC_STATS, statxbuf);
}

int
iou_statxat(reactor_t * reactor, int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_statx(sqe, dirfd, pathname, flags | AT_EMPTY_PATH, mask, statxbuf);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_statxfd(reactor_t * reactor, int fd, struct statx *statxbuf) {
    return iou_statxat(reactor, fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, statxbuf);
}

int
iou_symlink(reactor_t * reactor, const char *path1, const char *path2) {
    return iou_symlinkat(reactor, path1, AT_FDCWD, path2);
}

int
iou_symlinkat(reactor_t * reactor, const char *path1, int fd, const char *path2) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_symlinkat(sqe, path1, fd, path2);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_sync_file_range(reactor_t * reactor, int fd, off_t offset, off_t nbytes, bool wait) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    const unsigned int flags_no_wait = SYNC_FILE_RANGE_WRITE;
    const unsigned int flags_yes_wait = SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
    io_uring_prep_sync_file_range(sqe, fd, offset, nbytes, wait ? flags_yes_wait : flags_no_wait);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

ssize_t
iou_tee(reactor_t * reactor, int fd_in, int fd_out, size_t len) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_tee(sqe, fd_in, fd_out, len, SPLICE_F_MORE);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

int
iou_unlink(reactor_t * reactor, const char *pathname) {
    return iou_unlinkat(reactor, AT_FDCWD, pathname);
}

int
iou_unlinkat(reactor_t * reactor, int dirfd, const char *pathname) {
    assert(reactor);

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_unlinkat(sqe, dirfd, pathname, 0);
    reactor_promise(reactor, sqe);

    return reactor->result;
}

typedef struct _iou_vprintf_cookie_s {
    reactor_t * reactor;
    int fd;
} _iou_vprintf_cookie_t;

static
ssize_t _iou_vprintf_write(void *_cookie, const char *buf, size_t size) {
    _iou_vprintf_cookie_t *cookie = (_iou_vprintf_cookie_t*)_cookie;
    int n = iou_write(cookie->reactor, cookie->fd, buf, size);
    return n < 0 ? 0 : n;
}

static const cookie_io_functions_t _iou_vprintf_cookie_io_functions = {
    .write = _iou_vprintf_write,
};

int
iou_vprintf(reactor_t * reactor, int fd, const char *format, va_list args) {
    assert(reactor);

    va_list copy;
    va_copy(copy, args);

    char buffer[256];
    int result = vsnprintf(buffer, sizeof buffer, format, args);

    if (result >= sizeof buffer) {
        _iou_vprintf_cookie_t cookie = {
            .reactor = reactor,
            .fd = fd,
        };
        FILE *file = fopencookie(&cookie, "w", _iou_vprintf_cookie_io_functions);
        result = vfprintf(file, format, copy);
        fflush(file);
        fclose(file);
    } else if (result > 0) {
        result = iou_write(reactor, fd, buffer, result);
    }

    va_end(copy);
    return result;
}

ssize_t
iou_write(reactor_t * reactor, int fildes, const void *buf, size_t nbytes) {
    ssize_t out = 0;

    while (out < nbytes) {
        ssize_t n = iou_pwrite(reactor, fildes, buf + out, nbytes - out, -1);
        if (n < 0)
            return n;
        out += n;
    }

    return out;
}

void
iou_yield(reactor_t * reactor) {
    assert(reactor);

    if (!io_uring_cq_ready(&reactor->ring)) {
        TRY(io_uring_submit_and_get_events, &reactor->ring);
        if (!io_uring_cq_ready(&reactor->ring))
            return;
    }

    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_nop(sqe);
    reactor_promise(reactor, sqe);
}

//
