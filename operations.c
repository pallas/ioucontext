// SPDX-License-Identifier: MIT
#define _GNU_SOURCE

#include "operations.h"

#include "bitset.h"
#include "macros-internal.h"
#include "reactor-internal.h"
#include "stack.h"

#include <assert.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ucontext.h>

#define IOU_FLAGS(reactor, flags, operation, ...) ({ \
    reactor_t * _reactor = (reactor); \
    assert(_reactor); \
    struct io_uring_sqe * sqe = reactor_sqe(_reactor); \
    io_uring_prep_ ## operation(sqe __VA_OPT__(,) __VA_ARGS__); \
    io_uring_sqe_set_flags(sqe, flags); \
    reactor_promise(_reactor, sqe); \
})

#define IOU(reactor, operation, ...) ({ \
    IOU_FLAGS(reactor, 0, operation __VA_OPT__(,) __VA_ARGS__); \
})

#define IOU_FAKE_FLAGS(reactor, flags, operation, ...) do { \
    reactor_t * _reactor = (reactor); \
    assert(_reactor); \
    struct io_uring_sqe * sqe = reactor_sqe(_reactor); \
    io_uring_prep_ ## operation(sqe __VA_OPT__(,) __VA_ARGS__); \
    io_uring_sqe_set_flags(sqe, flags); \
    reactor_future_fake(_reactor, sqe); \
} while (false)

#define IOU_FAKE(reactor, operation, ...) \
    IOU_FAKE_FLAGS(reactor, 0, operation __VA_OPT__(,) __VA_ARGS__)

#define IOU_DELTA_EQUAL(l,r) ({ \
    const struct timespec _l = l; \
    const struct timespec _r = r; \
    _l.tv_sec == _r.tv_sec && _l.tv_nsec == _r.tv_nsec; \
})

#define IOU_DELTA_FLAGS(reactor, delta, flags, operation, ...) ({ \
    reactor_t * _reactor = (reactor); \
    assert(_reactor); \
    const struct timespec _delta = delta; \
    int result; \
    int when = \
        IOU_DELTA_EQUAL(_delta, timespec_block) ? -1 : \
        IOU_DELTA_EQUAL(_delta, timespec_zero) ? 0 : \
        timespec_when(normalize_timespec(_delta)); \
    switch (when) { \
    case -1: { \
        struct io_uring_sqe * sqe = reactor_sqe(_reactor); \
        io_uring_prep_ ## operation(sqe __VA_OPT__(,) __VA_ARGS__); \
        io_uring_sqe_set_flags(sqe, flags); \
        result = reactor_promise(_reactor, sqe); \
        } break; \
    case 0: { \
        reactor_reserve_sqes(_reactor, 2); \
        struct io_uring_sqe * sqe = reactor_sqe(_reactor); \
        io_uring_prep_ ## operation(sqe __VA_OPT__(,) __VA_ARGS__); \
        io_uring_sqe_set_flags(sqe, flags); \
        result = reactor_promise_nonchalant(_reactor, sqe); \
        } break; \
    case 1: { \
        struct timespec when = reify_timespec(_delta); \
        reactor_reserve_sqes(_reactor, 2); \
        struct io_uring_sqe * sqe = reactor_sqe(_reactor); \
        io_uring_prep_ ## operation(sqe __VA_OPT__(,) __VA_ARGS__); \
        io_uring_sqe_set_flags(sqe, flags); \
        result = reactor_promise_impatient(_reactor, sqe, when); \
        } break; \
    default: abort(); \
    } \
    result; \
})

#define IOU_DELTA(reactor, delta, operation, ...) ({ \
    IOU_DELTA_FLAGS(reactor, delta, 0, operation __VA_OPT__(,) __VA_ARGS__); \
})

enum { registered_file_flag = 1<<30 };
#define FD_FIXED(fd) ({ assert(AT_FDCWD != fd); (bool)(fd & registered_file_flag); })
#define FD_VALUE(fd) ({ assert(AT_FDCWD != fd); (int)(fd & ~registered_file_flag); })
#define FD_FLAGS(fd) ({ assert(AT_FDCWD != fd); FD_FIXED(fd) ? IOSQE_FIXED_FILE : 0; })
#define FD_BUILD(fd) ({ assert(!FD_FIXED(fd)); (int)(fd | registered_file_flag); })

#define DIRFD_FIXED(fd) ({ (bool)((AT_FDCWD != fd) && FD_FIXED(fd)); })
#define DIRFD_VALUE(fd) ({ (int)((AT_FDCWD != fd) ? FD_VALUE(fd) : AT_FDCWD); })
#define DIRFD_FLAGS(fd) ({ DIRFD_FIXED(fd) ? IOSQE_FIXED_FILE : 0; })

int
iou_accept(reactor_t * reactor, int fd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    assert(addrlen || !addr);

    if (addr) VALGRIND_CHECK_MEM_IS_ADDRESSABLE(addr, *addrlen);

    int result = IOU_FLAGS(reactor, FD_FLAGS(fd), accept, FD_VALUE(fd), addr, addrlen, flags);

    if (addr && result >= 0)
        VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(addr, *addrlen);

    return result;
}

int
iou_accept_direct(reactor_t * reactor, int fd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    ssize_t index = bitset_get(reactor->registered_file_bits);
    if (index < 0)
        return iou_accept(reactor, fd, addr, addrlen, flags);

    assert(addrlen || !addr);

    if (addr) VALGRIND_CHECK_MEM_IS_ADDRESSABLE(addr, *addrlen);

    int result = IOU_FLAGS(reactor, FD_FLAGS(fd), accept_direct, FD_VALUE(fd), addr, addrlen, flags & ~SOCK_CLOEXEC, index);

    if (addr && result >= 0)
        VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(addr, *addrlen);

    if (result < 0) {
        bitset_put(reactor->registered_file_bits, index);
        return result;
    }

    return FD_BUILD(index);
}

void
iou_barrier(reactor_t * reactor) {
    IOU_FAKE_FLAGS(reactor, IOSQE_IO_DRAIN, nop);
}

int
iou_bind(reactor_t * reactor, int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    VALGRIND_CHECK_MEM_IS_DEFINED(addr, addrlen);

    return IOU_FLAGS(reactor, FD_FLAGS(sockfd), bind, FD_VALUE(sockfd), (struct sockaddr *)addr, addrlen);
}

void
iou_cancel_fd_all(reactor_t * reactor, int fd) {
    IOU_FAKE_FLAGS(reactor, FD_FLAGS(fd), cancel_fd, FD_VALUE(fd), IORING_ASYNC_CANCEL_ALL);
}

void
iou_cancel_fd_any(reactor_t * reactor, int fd) {
    IOU_FAKE_FLAGS(reactor, FD_FLAGS(fd), cancel_fd, FD_VALUE(fd), 0);
}

int
iou_close(reactor_t * reactor, int fd) {
    if (!FD_FIXED(fd))
        return IOU(reactor, close, fd);

    int index = FD_VALUE(fd);
    int result = IOU(reactor, close_direct, index);
    bitset_put(reactor->registered_file_bits, index);
    return result;
}

void
iou_close_fast(reactor_t * reactor, int fd) {
    if (!FD_FIXED(fd)) {
        IOU_FAKE(reactor, close, fd);
    } else {
        int no_fd = -1;
        const int index = FD_VALUE(fd);
        if (UNLIKELY(1 != IOU(reactor, files_update, &no_fd, 1, index)))
            abort();

        bitset_put(reactor->registered_file_bits, index);
    }
}

int
iou_connect(reactor_t * reactor, int sockfd, const struct sockaddr *addr, socklen_t addrlen, const struct timespec delta) {
    VALGRIND_CHECK_MEM_IS_DEFINED(addr, addrlen);

    return IOU_DELTA_FLAGS(reactor, delta, FD_FLAGS(sockfd), connect, FD_VALUE(sockfd), addr, addrlen);
}

int
iou_discard(reactor_t * reactor, int fd, off_t offset, off_t len) {
    return IOU_FLAGS(reactor, FD_FLAGS(fd), cmd_discard, FD_VALUE(fd), offset, len);
}

int
iou_epoll_add(reactor_t * reactor, int epfd, int fd, struct epoll_event *event) {
    return iou_epoll_ctl(reactor, epfd, EPOLL_CTL_ADD, fd, event);
}

int
iou_epoll_ctl(reactor_t * reactor, int epfd, int op, int fd, struct epoll_event *event) {
    if (event) {
        VALGRIND_CHECK_MEM_IS_ADDRESSABLE(event, sizeof *event);
        VALGRIND_CHECK_VALUE_IS_DEFINED(event->events);
    }

    if (UNLIKELY(FD_FIXED(fd)))
        return -ENOTSUP;

    return IOU_FLAGS(reactor, FD_FLAGS(epfd), epoll_ctl, FD_VALUE(epfd), fd, op, event);
}

int
iou_epoll_del(reactor_t * reactor, int epfd, int fd) {
    return iou_epoll_ctl(reactor, epfd, EPOLL_CTL_DEL, fd, NULL);
}

int
iou_epoll_mod(reactor_t * reactor, int epfd, int fd, struct epoll_event *event) {
    return iou_epoll_ctl(reactor, epfd, EPOLL_CTL_MOD, fd, event);
}

int
iou_epoll_set(reactor_t * reactor, int epfd, int fd, struct epoll_event *event) {
    int result = iou_epoll_mod(reactor, epfd, fd, event);
    if (result == -ENOENT)
        result = iou_epoll_add(reactor, epfd, fd, event);
    return result;
}

int
iou_epoll_wait(reactor_t * reactor, int epfd, struct epoll_event *events, int maxevents, const struct timespec delta) {
    VALGRIND_CHECK_MEM_IS_ADDRESSABLE(events, maxevents * sizeof *events);
    int result = IOU_DELTA(reactor, delta, epoll_wait, epfd, events, maxevents, 0);
    if (result > 0)
        VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(events, result * sizeof *events);
    return result;
}

int
iou_exchange(reactor_t * reactor, const char *oldpath, const char *newpath) {
    return iou_exchangeat(reactor, AT_FDCWD, oldpath, newpath);
}

int
iou_exchangeat(reactor_t * reactor, int dirfd, const char *oldpath, const char *newpath) {
    return iou_renameat(reactor, dirfd, oldpath, dirfd, newpath, RENAME_EXCHANGE);
}

bool
iou_exists(reactor_t * reactor, const char *pathname) {
    struct statx buf;
    return !iou_statxat(reactor, AT_FDCWD, pathname, 0, STATX_ALL, &buf);
}

int
iou_fadvise(reactor_t * reactor, int fd, off_t offset, off_t len, int advice) {
    return IOU_FLAGS(reactor, FD_FLAGS(fd), fadvise, FD_VALUE(fd), offset, len, advice);
}

void
iou_fadvise_fast(reactor_t * reactor, int fd, off_t offset, off_t len, int advice) {
    IOU_FAKE_FLAGS(reactor, FD_FLAGS(fd), fadvise, FD_VALUE(fd), offset, len, advice);
}

int
iou_fallocate(reactor_t * reactor, int fd, int mode, off_t offset, off_t len) {
    return IOU_FLAGS(reactor, FD_FLAGS(fd), fallocate, FD_VALUE(fd), mode, offset, len);
}

bool
iou_fd_fixed(reactor_t * reactor, int fd) {
    return FD_FIXED(fd);
}

int
iou_fd_getlock(reactor_t * reactor, int fd, struct flock *lock) {
    VALGRIND_CHECK_MEM_IS_DEFINED(lock, sizeof *lock);

    if (UNLIKELY(FD_FIXED(fd)))
        return -ENOTSUP;

    return fcntl(fd, F_OFD_GETLK, lock) ? -errno : 0;
}

int
iou_fd_install(reactor_t * reactor, int fd) {
    if (UNLIKELY(fd < 0))
        return fd;

    if (UNLIKELY(!FD_FIXED(fd)))
        return -ENOENT;

    return IOU_FLAGS(reactor, IOSQE_FIXED_FILE, fixed_fd_install, FD_VALUE(fd), 0);
}

int
iou_fd_install_no_cloexec(reactor_t * reactor, int fd) {
    if (UNLIKELY(fd < 0))
        return fd;

    if (UNLIKELY(!FD_FIXED(fd)))
        return -ENOENT;

    return IOU_FLAGS(reactor, IOSQE_FIXED_FILE, fixed_fd_install, FD_VALUE(fd), IORING_FIXED_FD_NO_CLOEXEC);
}

int
iou_fd_lock_append(reactor_t * reactor, int fd, off_t length, const struct timespec delta) {
    struct flock lock = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_END,
        .l_start = 0,
        .l_len = length,
    };
    return iou_fd_setlock(reactor, fd, &lock, delta);
}

int
iou_fd_lock_read(reactor_t * reactor, int fd, off_t start, off_t length, const struct timespec delta) {
    struct flock lock = {
        .l_type = F_RDLCK,
        .l_whence = start < 0 ? SEEK_END: SEEK_SET,
        .l_start = start,
        .l_len = length,
    };
    return iou_fd_setlock(reactor, fd, &lock, delta);
}

int
iou_fd_lock_write(reactor_t * reactor, int fd, off_t start, off_t length, const struct timespec delta) {
    struct flock lock = {
        .l_type = F_WRLCK,
        .l_whence = start < 0 ? SEEK_END : SEEK_SET,
        .l_start = start,
        .l_len = length,
    };
    return iou_fd_setlock(reactor, fd, &lock, delta);
}

int
iou_fd_register(reactor_t * reactor, int fd) {
    if (UNLIKELY(fd < 0))
        return fd;

    if (UNLIKELY(FD_FIXED(fd)))
        return fd;

    if (UNLIKELY(!reactor->registered_file_bits))
        return fd;

    ssize_t index = bitset_get(reactor->registered_file_bits);
    if (UNLIKELY(index < 0))
        return fd;

    if (UNLIKELY(1 != IOU(reactor, files_update, &fd, 1, index))) {
        bitset_put(reactor->registered_file_bits, index);
        return fd;
    }

    return FD_BUILD(index);
}

int
iou_fd_setlock(reactor_t * reactor, int fd, const struct flock *lock, const struct timespec delta) {
    assert(reactor);

    VALGRIND_CHECK_MEM_IS_DEFINED(lock, sizeof *lock);

    if (UNLIKELY(FD_FIXED(fd)))
        return -ENOTSUP;

    int when =
        IOU_DELTA_EQUAL(delta, timespec_block) ? -1 :
        IOU_DELTA_EQUAL(delta, timespec_zero) ? 0 :
        timespec_when(normalize_timespec(delta));

    switch (when) {
    case -1: {
        int result = fcntl(fd, F_OFD_SETLK, lock);
        while (result && (errno == EACCES || errno == EAGAIN || errno == EINTR))
            result = iou_yield(reactor) ? fcntl(fd, F_OFD_SETLK, lock) : fcntl(fd, F_OFD_SETLKW, lock);
        return result ? -errno : 0;
        } break;

    case 0: {
        return fcntl(fd, F_OFD_SETLK, lock) ? -errno : 0;
        } break;

    case 1: {
        struct timespec when = reify_timespec(delta);
        int result = fcntl(fd, F_OFD_SETLK, lock);
        while (result && (errno == EACCES || errno == EAGAIN || errno == EINTR) && timespec_future(dereify_timespec(when))) {
            iou_yield(reactor);
            result = fcntl(fd, F_OFD_SETLK, lock);
        }
        return result ? -errno : 0;
        } break;

    default: abort();
    }

    return 0;
}

ssize_t
iou_fd_size(reactor_t * reactor, int fd) {
    struct statx buf;

    int result = iou_statxat(reactor, fd, "", AT_EMPTY_PATH, STATX_SIZE, &buf);
    if (result < 0)
        return result;

    return buf.stx_size;
}

int
iou_fd_transmute(reactor_t * reactor, int fd) {
    if (UNLIKELY(fd < 0))
        return fd;

    if (UNLIKELY(FD_FIXED(fd)))
        return fd;

    if (UNLIKELY(!reactor->registered_file_bits))
        return fd;

    ssize_t index = bitset_get(reactor->registered_file_bits);
    if (UNLIKELY(index < 0))
        return fd;

    reactor_reserve_sqes(reactor, 2);
    struct io_uring_sqe * sqe[2];
    sqe[0] = reactor_sqe(reactor);
    sqe[1] = reactor_sqe(reactor);

    io_uring_prep_files_update(sqe[0], &fd, 1, index);
    io_uring_sqe_set_flags(sqe[0], IOSQE_IO_LINK);

    io_uring_prep_close(sqe[1], fd);
    reactor_future_fake(reactor, sqe[1]);

    if (UNLIKELY(1 != reactor_promise(reactor, sqe[0]))) {
        bitset_put(reactor->registered_file_bits, index);
        return fd;
    }

    return FD_BUILD(index);
}

int
iou_fd_unlock(reactor_t * reactor, int fd, off_t start, off_t length) {
    struct flock lock = {
        .l_type = F_UNLCK,
        .l_whence = start < 0 ? SEEK_END : SEEK_SET,
        .l_start = start,
        .l_len = length,
    };
    return iou_fd_setlock(reactor, fd, &lock, timespec_block);
}

int
iou_fdatasync(reactor_t * reactor, int fd) {
    return IOU_FLAGS(reactor, FD_FLAGS(fd), fsync, FD_VALUE(fd), IORING_FSYNC_DATASYNC);
}

int
iou_fdatasync_range(reactor_t * reactor, int fd, off_t start, off_t length) {
    assert(reactor);
    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_fsync(sqe, FD_VALUE(fd), IORING_FSYNC_DATASYNC);
    io_uring_sqe_set_flags(sqe, FD_FLAGS(fd));
    sqe->off = start;
    sqe->len = length;
    return reactor_promise(reactor, sqe);
}

typedef struct _iou_cookie_s {
    reactor_t * reactor;
    int fd;
    off_t offset;
} _iou_cookie_t;

static
ssize_t _iou_cookie_read(void *_cookie, char *buf, size_t size) {
    _iou_cookie_t *cookie = (_iou_cookie_t*)_cookie;
    assert(!cookie->reactor || cookie->reactor == reactor_get());
    ssize_t n = ERRNO(iou_pread, cookie->reactor ?: reactor_get(), cookie->fd, buf, size, cookie->offset);
    if (n > 0 && cookie->offset >= 0)
        cookie->offset += n;
    return n;
}

static
ssize_t _iou_cookie_write(void *_cookie, const char *buf, size_t size) {
    _iou_cookie_t *cookie = (_iou_cookie_t*)_cookie;
    assert(!cookie->reactor || cookie->reactor == reactor_get());
    ssize_t n = ERRNO(iou_pwrite, cookie->reactor ?: reactor_get(), cookie->fd, buf, size, cookie->offset);
    if (n > 0 && cookie->offset >= 0)
        cookie->offset += n;
    return n < 0 ? 0 : n;
}

static
int _iou_cookie_seek_errno(void *_cookie, off_t *offset, int whence) {
    _iou_cookie_t *cookie = (_iou_cookie_t*)_cookie;
    assert(!cookie->reactor || cookie->reactor == reactor_get());

    if (cookie->offset < 0)
        return -ESPIPE;

    off_t target;

    switch (whence) {

    case SEEK_SET: {
        target = *offset;
    } break;

    case SEEK_CUR: {
        if (__builtin_add_overflow(cookie->offset, *offset, &target))
            return -EINVAL;
    } break;

    case SEEK_END: {
        ssize_t end = iou_fd_size(cookie->reactor ?: reactor_get(), cookie->fd);
        if (end < 0)
            return end;

        if (__builtin_add_overflow(end, *offset, &target))
            return -EINVAL;
    } break;

    default:
        return -EINVAL;
    }

    if (target < 0)
        return -EINVAL;

    cookie->offset = target;
    *offset = cookie->offset;
    return 0;
}

static
int _iou_cookie_seek(void *_cookie, off_t *offset, int whence) {
    return ERRNO(_iou_cookie_seek_errno, _cookie, offset, whence);
}

static
int _iou_cookie_close(void *_cookie) {
    _iou_cookie_t *cookie = (_iou_cookie_t*)_cookie;
    assert(!cookie->reactor || cookie->reactor == reactor_get());
    int result = ERRNO(iou_close, cookie->reactor ?: reactor_get(), cookie->fd);
    free(cookie);
    return result;
}

FILE *
iou_fdopen(reactor_t * reactor, int fd, const char *mode) {
    _iou_cookie_t *cookie = (_iou_cookie_t*)malloc(sizeof(_iou_cookie_t));
    if (UNLIKELY(!cookie))
        return NULL;
    *cookie = (_iou_cookie_t){
        .reactor = reactor,
        .fd = fd,
        .offset = (!FD_FIXED(fd)) ? lseek(fd, 0, SEEK_CUR) : -1,
    };
    static const cookie_io_functions_t cookie_io = {
        .read = _iou_cookie_read,
        .write = _iou_cookie_write,
        .seek = _iou_cookie_seek,
        .close = _iou_cookie_close,
    };
    return fopencookie(cookie, mode, cookie_io);
}

int
iou_fgetxattr(reactor_t * reactor, int fd, const char *name, void *value, size_t size) {
    VALGRIND_CHECK_STRING(name);
    VALGRIND_CHECK_MEM_IS_ADDRESSABLE(value, size);
    VALGRIND_MAKE_MEM_UNDEFINED(value, size);

    int result = IOU_FLAGS(reactor, FD_FLAGS(fd), fgetxattr, FD_VALUE(fd), name, value, size);

    VALGRIND_MAKE_BUFFER_DEFINED(value, result, size);

    return result;
}

void
iou_flush(reactor_t * reactor) {
    IOU_FLAGS(reactor, IOSQE_IO_DRAIN, nop);
}

int
iou_fsetxattr(reactor_t * reactor, int fd, const char *name, const void *value, size_t size, int flags) {
    VALGRIND_CHECK_STRING(name);
    VALGRIND_CHECK_MEM_IS_DEFINED(value, size);

    return IOU_FLAGS(reactor, FD_FLAGS(fd), fsetxattr, FD_VALUE(fd), name, value, size, flags);
}

int
iou_fsync(reactor_t * reactor, int fd) {
    return IOU_FLAGS(reactor, FD_FLAGS(fd), fsync, FD_VALUE(fd), 0);
}

int
iou_fsync_range(reactor_t * reactor, int fd, off_t start, off_t length) {
    assert(reactor);
    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_fsync(sqe, FD_VALUE(fd), 0);
    io_uring_sqe_set_flags(sqe, FD_FLAGS(fd));
    sqe->off = start;
    sqe->len = length;
    return reactor_promise(reactor, sqe);
}

int
iou_ftruncate(reactor_t * reactor, int fildes, off_t length) {
    return IOU_FLAGS(reactor, FD_FLAGS(fildes), ftruncate, FD_VALUE(fildes), length);
}

int
iou_futex_wait32(reactor_t * reactor, uint32_t *futex, uint32_t value, const struct timespec delta) {
    VALGRIND_CHECK_MEM_IS_ADDRESSABLE(futex, sizeof *futex);
    return IOU_DELTA(reactor, delta, futex_wait, futex, value, FUTEX_BITSET_MATCH_ANY, 0 | FUTEX_32 | FUTEX_PRIVATE_FLAG, 0);
}

int
iou_futex_wait32_bitset(reactor_t * reactor, uint32_t *futex, uint32_t value, uint32_t mask, const struct timespec delta) {
    VALGRIND_CHECK_MEM_IS_ADDRESSABLE(futex, sizeof *futex);
    return IOU_DELTA(reactor, delta, futex_wait, futex, value, mask, 0 | FUTEX_32 | FUTEX_PRIVATE_FLAG, 0);
}

int
iou_futex_waitv(reactor_t * reactor, struct futex_waitv *futexv, uint32_t nr_futex, const struct timespec delta) {
    VALGRIND_CHECK_MEM_IS_DEFINED(futexv, nr_futex * sizeof *futexv);
    return IOU_DELTA(reactor, delta, futex_waitv, futexv, nr_futex, 0);
}

int
iou_futex_waitv_absolute(reactor_t * reactor, struct futex_waitv *futexv, uint32_t nr_futex, const struct timespec when) {
    VALGRIND_CHECK_MEM_IS_DEFINED(futexv, nr_futex * sizeof *futexv);
    reactor_reserve_sqes(reactor, 2);
    struct io_uring_sqe * sqe = reactor_sqe(reactor);
    io_uring_prep_futex_waitv(sqe, futexv, nr_futex, 0);
    io_uring_sqe_set_flags(sqe, 0);
    return reactor_promise_impatient(reactor, sqe, when);
}

int
iou_futex_wake32(reactor_t * reactor, uint32_t *futex, int n) {
    return iou_futex_wake32_bitset(reactor, futex, FUTEX_BITSET_MATCH_ANY, n);
}

void
iou_futex_wake32_fast(reactor_t * reactor, uint32_t *futex, int n) {
    return iou_futex_wake32_bitset_fast(reactor, futex, FUTEX_BITSET_MATCH_ANY, n);
}

int
iou_futex_wake32_bitset(reactor_t * reactor, uint32_t *futex, uint32_t mask, int n) {
    VALGRIND_CHECK_MEM_IS_ADDRESSABLE(futex, sizeof *futex);
    return IOU(reactor, futex_wake, futex, n, mask, 0 | FUTEX_32 | FUTEX_PRIVATE_FLAG, 0);
}

void
iou_futex_wake32_bitset_fast(reactor_t * reactor, uint32_t *futex, uint32_t mask, int n) {
    VALGRIND_CHECK_MEM_IS_ADDRESSABLE(futex, sizeof *futex);
    IOU_FAKE(reactor, futex_wake, futex, n, mask, 0 | FUTEX_32 | FUTEX_PRIVATE_FLAG, 0);
}

ssize_t
iou_getrandom(reactor_t * reactor, char *buf, size_t buflen) {
    if (reactor->urandomfd < 0) {
        reactor->urandomfd = iou_open_direct(reactor, "/dev/urandom", O_RDONLY | O_CLOEXEC, 0);
        if (reactor->urandomfd < 0)
            return reactor->urandomfd;
    }

    return iou_read(reactor, reactor->urandomfd, buf, buflen);
}

int
iou_getsockopt(reactor_t * reactor, int socket, int level, int option_name, void *option_value, socklen_t *option_len) {
    VALGRIND_CHECK_MEM_IS_ADDRESSABLE(option_value, *option_len);
    VALGRIND_MAKE_MEM_UNDEFINED(option_value, *option_len);

    int result = IOU_FLAGS(reactor, FD_FLAGS(socket), cmd_sock, SOCKET_URING_OP_GETSOCKOPT, FD_VALUE(socket), level, option_name, option_value, *option_len);

    if (result < 0)
        return result;

    VALGRIND_MAKE_BUFFER_DEFINED(option_value, result, *option_len);
    *option_len = result;

    return 0;
}

int
iou_getsockopt_int(reactor_t * reactor, int socket, int level, int option_name) {
    int option_value;
    socklen_t option_len = sizeof option_value;
    int result = iou_getsockopt(reactor, socket, level, option_name, &option_value, &option_len);
    assert(result < 0 || sizeof option_value == option_len);
    return result < 0 ? result : option_value;
}

int
iou_getxattr(reactor_t * reactor, const char *path, const char *name, void *value, size_t size) {
    VALGRIND_CHECK_STRING(path);
    VALGRIND_CHECK_STRING(name);
    VALGRIND_CHECK_MEM_IS_ADDRESSABLE(value, size);
    VALGRIND_MAKE_MEM_UNDEFINED(value, size);

    int result = IOU(reactor, getxattr, name, value, path, size);

    VALGRIND_MAKE_BUFFER_DEFINED(result, result, size);

    return result;
}

int
iou_link(reactor_t * reactor, const char *oldpath, const char *newpath) {
    return iou_linkat(reactor, AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
}

int iou_linkat(reactor_t * reactor, int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
    VALGRIND_CHECK_STRING(oldpath);
    VALGRIND_CHECK_STRING(newpath);

    if (!oldpath || !*oldpath)
        flags |= AT_EMPTY_PATH;

    if (DIRFD_FIXED(newdirfd))
        return -ENOTSUP;

    return IOU_FLAGS(reactor, DIRFD_FLAGS(olddirfd), linkat, DIRFD_VALUE(olddirfd), oldpath, newdirfd, newpath, flags);
}

int
iou_listen(reactor_t * reactor, int sockfd, int backlog) {
    return IOU_FLAGS(reactor, FD_FLAGS(sockfd), listen, FD_VALUE(sockfd), backlog);
}

int
iou_madvise(reactor_t * reactor, void *addr, size_t len, int advice) {
    return IOU(reactor, madvise, addr, len, advice);
}

void
iou_madvise_fast(reactor_t * reactor, void *addr, size_t len, int advice) {
    IOU_FAKE(reactor, madvise, addr, len, advice);
}

int
iou_mkdir(reactor_t * reactor, const char *pathname, mode_t mode) {
    return iou_mkdirat(reactor, AT_FDCWD, pathname, mode);
}

int
iou_mkdirat(reactor_t * reactor, int dirfd, const char *pathname, mode_t mode) {
    VALGRIND_CHECK_STRING(pathname);

    return IOU_FLAGS(reactor, DIRFD_FLAGS(dirfd), mkdirat, DIRFD_VALUE(dirfd), pathname, mode);
}

int
iou_open(reactor_t * reactor, const char *pathname, int flags, mode_t mode) {
    return iou_openat(reactor, AT_FDCWD, pathname, flags, mode);
}

int
iou_open_direct(reactor_t * reactor, const char *pathname, int flags, mode_t mode) {
    return iou_openat_direct(reactor, AT_FDCWD, pathname, flags, mode);
}

int
iou_openat(reactor_t * reactor, int dirfd, const char *pathname, int flags, mode_t mode) {
    VALGRIND_CHECK_STRING(pathname);

    return IOU_FLAGS(reactor, DIRFD_FLAGS(dirfd), openat, DIRFD_VALUE(dirfd), pathname, flags, mode);
}

int
iou_openat_direct(reactor_t * reactor, int dirfd, const char *pathname, int flags, mode_t mode) {
    ssize_t index = bitset_get(reactor->registered_file_bits);
    if (index < 0)
        return iou_openat(reactor, dirfd, pathname, flags, mode);

    VALGRIND_CHECK_STRING(pathname);

    int result = IOU_FLAGS(reactor, DIRFD_FLAGS(dirfd), openat_direct, DIRFD_VALUE(dirfd), pathname, flags & ~O_CLOEXEC, mode, index);

    if (result < 0) {
        bitset_put(reactor->registered_file_bits, index);
        return result;
    }

    return FD_BUILD(index);
}

int
iou_pipe(reactor_t * reactor, int *read_fd, int *write_fd, int flags) {
    int pipefd[2];
    int result = IOU(reactor, pipe, pipefd, flags);

    if (result < 0)
        result = pipe2(pipefd, flags);

    if (result < 0)
        return result;

    VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(pipefd, sizeof pipefd);
    *read_fd = pipefd[0];
    *write_fd = pipefd[1];

    return 0;
}

int
iou_pipe_direct(reactor_t * reactor, int *read_fd, int *write_fd, int flags) {
    ssize_t index = bitset_two(reactor->registered_file_bits);
    if (index < 0)
        return iou_pipe(reactor, read_fd, write_fd, flags);

    int pipefd[2];
    int result = IOU(reactor, pipe_direct, pipefd, flags, index);
    if (result < 0) {
        bitset_put(reactor->registered_file_bits, index+0);
        bitset_put(reactor->registered_file_bits, index+1);
        return result;
    }

    VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(pipefd, sizeof pipefd);
    *read_fd = FD_BUILD(pipefd[0]);
    *write_fd = FD_BUILD(pipefd[1]);

    return 0;
}

static unsigned
iou_poll_mask(reactor_t * reactor, int fd, unsigned mask, const struct timespec delta) {
    int result = IOU_DELTA_FLAGS(reactor, delta, FD_FLAGS(fd), poll_add, FD_VALUE(fd), mask);
    if (result < 0)
        return 0;
    if (UNLIKELY(result & POLLNVAL))
        abort();
    return result;
}

unsigned
iou_poll(reactor_t * reactor, int fd, unsigned events, const struct timespec delta) {
    return iou_poll_mask(reactor, fd, events, delta);
}

unsigned
iou_poll_any(reactor_t * reactor, int fd, const struct timespec delta) {
    static const unsigned mask = POLLERR | POLLHUP | POLLIN | POLLOUT | POLLPRI | POLLRDHUP;
    return iou_poll_mask(reactor, fd, mask, delta);
}

bool
iou_poll_hup(reactor_t * reactor, int fd, const struct timespec delta) {
    static const unsigned mask = POLLHUP | POLLRDHUP;
    static const unsigned fail = POLLERR;
    unsigned events = iou_poll_mask(reactor, fd, mask | fail, delta);
    return !!(events & mask) && !(events & fail);
}

bool
iou_poll_in(reactor_t * reactor, int fd, const struct timespec delta) {
    static const unsigned mask = POLLIN | POLLPRI;
    static const unsigned fail = POLLERR | POLLHUP;
    unsigned events = iou_poll_mask(reactor, fd, mask | fail | POLLRDHUP, delta);
    return !!(events & mask) && !(events & fail);
}

bool
iou_poll_out(reactor_t * reactor, int fd, const struct timespec delta) {
    static const unsigned mask = POLLOUT;
    static const unsigned fail = POLLERR | POLLHUP;
    unsigned events = iou_poll_mask(reactor, fd, mask | fail, delta);
    return !!(events & mask) && !(events & fail);
}

ssize_t
iou_pread(reactor_t * reactor, int fildes, void *buf, size_t nbytes, off_t offset) {
    VALGRIND_CHECK_MEM_IS_ADDRESSABLE(buf, nbytes);
    VALGRIND_MAKE_MEM_UNDEFINED(buf, nbytes);

    int result = IOU_FLAGS(reactor, FD_FLAGS(fildes), read, FD_VALUE(fildes), buf, nbytes, offset);

    VALGRIND_MAKE_BUFFER_DEFINED(buf, result, nbytes);

    return result;
}

ssize_t
iou_preadv(reactor_t * reactor, int fildes, const struct iovec *iov, int iovcnt, off_t offset, int flags) {
    if (RUNNING_ON_VALGRIND) {
        for (int i = 0 ; i < iovcnt ; ++i) {
            const void * buf = iov[i].iov_base;
            size_t nbytes = iov[i].iov_len;
            VALGRIND_CHECK_MEM_IS_ADDRESSABLE(buf, nbytes);
            VALGRIND_MAKE_MEM_UNDEFINED(buf, nbytes);
        }
    }

    int result = IOU_FLAGS(reactor, FD_FLAGS(fildes), readv2, FD_VALUE(fildes), iov, iovcnt, offset, flags);

    if (RUNNING_ON_VALGRIND) {
        ssize_t bytes = result;
        for (int i = 0 ; i < iovcnt && bytes > 0 ; ++i) {
            const void * buf = iov[i].iov_base;
            size_t nbytes = iov[i].iov_len;
            VALGRIND_MAKE_BUFFER_DEFINED(buf, bytes, nbytes);
            bytes -= nbytes;
        }
    }

    return result;
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
    VALGRIND_CHECK_MEM_IS_DEFINED(buf, nbytes);
    return IOU_FLAGS(reactor, FD_FLAGS(fildes), write, FD_VALUE(fildes), buf, nbytes, offset);
}

ssize_t
iou_pwritev(reactor_t * reactor, int fildes, const struct iovec *iov, int iovcnt, off_t offset, int flags) {
    if (RUNNING_ON_VALGRIND) {
        for (int i = 0 ; i < iovcnt ; ++i) {
            const void * buf = iov[i].iov_base;
            size_t nbytes = iov[i].iov_len;
            VALGRIND_CHECK_MEM_IS_DEFINED(buf, nbytes);
        }
    }

    return IOU_FLAGS(reactor, FD_FLAGS(fildes), writev2, FD_VALUE(fildes), iov, iovcnt, offset, flags);
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
    VALGRIND_CHECK_MEM_IS_DEFINED(address, address_len);
    VALGRIND_CHECK_MEM_IS_ADDRESSABLE(buffer, length);
    VALGRIND_MAKE_MEM_UNDEFINED(buffer, length);

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

    int result = IOU_FLAGS(reactor, FD_FLAGS(socket), recvmsg, FD_VALUE(socket), &msg, flags);

    VALGRIND_MAKE_BUFFER_DEFINED(buffer, result, length);

    return result;
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
    VALGRIND_CHECK_STRING(oldpath);
    VALGRIND_CHECK_STRING(newpath);

    if (DIRFD_FIXED(newdirfd))
        return -ENOTSUP;

    return IOU_FLAGS(reactor, DIRFD_FLAGS(olddirfd), renameat, DIRFD_VALUE(olddirfd), oldpath, newdirfd, newpath, flags);
}

int
iou_rmdir(reactor_t * reactor, const char *pathname) {
    return iou_rmdirat(reactor, AT_FDCWD, pathname);
}

int
iou_rmdirat(reactor_t * reactor, int dirfd, const char *pathname) {
    VALGRIND_CHECK_STRING(pathname);

    return IOU_FLAGS(reactor, DIRFD_FLAGS(dirfd), unlinkat, DIRFD_VALUE(dirfd), pathname, AT_REMOVEDIR);
}

int
iou_scanf(reactor_t * reactor, int fd, const char *format, ...) {
    int result;
    va_list args;
    va_start(args, format);
    result = iou_vscanf(reactor, fd, format, args);
    va_end(args);
    return result;
}

ssize_t
iou_send(reactor_t * reactor, int socket, const void *buffer, size_t length, int flags) {
    return iou_sendto(reactor, socket, buffer, length, flags, NULL, 0);
}

ssize_t
iou_sendto(reactor_t * reactor, int socket, const void *message, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t dest_len) {
    VALGRIND_CHECK_MEM_IS_DEFINED(message, length);
    VALGRIND_CHECK_MEM_IS_DEFINED(dest_addr, dest_len);

    enum { zero_copy_threshold = 1<<15 };

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

    return length >= zero_copy_threshold
        ? IOU_FLAGS(reactor, FD_FLAGS(socket), sendmsg_zc, FD_VALUE(socket), &msg, flags)
        : IOU_FLAGS(reactor, FD_FLAGS(socket), sendmsg, FD_VALUE(socket), &msg, flags)
        ;
}

int
iou_setxattr(reactor_t * reactor, const char *path, const char *name, const void *value, size_t size, int flags) {
    VALGRIND_CHECK_STRING(path);
    VALGRIND_CHECK_MEM_IS_DEFINED(value, size);

    return IOU(reactor, setxattr, name, value, path, size, flags);
}

int
iou_setsockopt(reactor_t * reactor, int socket, int level, int option_name, const void *option_value, socklen_t option_len) {
    VALGRIND_CHECK_MEM_IS_DEFINED(option_value, option_len);

    return IOU_FLAGS(reactor, FD_FLAGS(socket), cmd_sock, SOCKET_URING_OP_SETSOCKOPT, FD_VALUE(socket), level, option_name, (void *)option_value, option_len);
}

int
iou_setsockopt_int(reactor_t * reactor, int socket, int level, int option_name, int option_value) {
    return iou_setsockopt(reactor, socket, level, option_name, &option_value, sizeof option_value);
}

int
iou_shutdown(reactor_t * reactor, int sockfd) {
    return IOU_FLAGS(reactor, FD_FLAGS(sockfd), shutdown, FD_VALUE(sockfd), SHUT_RDWR);
}

int
iou_shutdown_read(reactor_t * reactor, int sockfd) {
    return IOU_FLAGS(reactor, FD_FLAGS(sockfd), shutdown, FD_VALUE(sockfd), SHUT_RD);
}

int
iou_shutdown_write(reactor_t * reactor, int sockfd) {
    return IOU_FLAGS(reactor, FD_FLAGS(sockfd), shutdown, FD_VALUE(sockfd), SHUT_WR);
}

int
iou_siocinq(reactor_t * reactor, int socket) {
    return IOU_FLAGS(reactor, FD_FLAGS(socket), cmd_sock, SOCKET_URING_OP_SIOCINQ, FD_VALUE(socket), 0, 0, NULL, 0);
}

int
iou_siocoutq(reactor_t * reactor, int socket) {
    return IOU_FLAGS(reactor, FD_FLAGS(socket), cmd_sock, SOCKET_URING_OP_SIOCOUTQ, FD_VALUE(socket), 0, 0, NULL, 0);
}

struct timespec
iou_sleep(reactor_t * reactor, const struct timespec delta) {
    assert(reactor);

    const struct timespec when = reify_timespec(delta);

    if (iou_sleep_absolute(reactor, when))
        return timespec_zero;

    const struct timespec remaining = dereify_timespec(when);

    if (remaining.tv_sec < 0)
        return timespec_zero;

    return remaining;
}

bool
iou_sleep_absolute(reactor_t * reactor, const struct timespec when) {
    const struct timespec ts = normalize_timespec(when);
    struct __kernel_timespec kts = {
        .tv_sec = ts.tv_sec,
        .tv_nsec = ts.tv_nsec,
    };

    while (true) {
        int result = IOU(reactor, timeout, &kts, 0, 0
            | IORING_TIMEOUT_ABS
            | IORING_TIMEOUT_BOOTTIME
        );

        switch (result) {
        case 0: continue;
        case -ETIME: return true;
        default: return false;
        }
    }
}

int
iou_socket(reactor_t * reactor, int domain, int type, int protocol) {
    return IOU(reactor, socket, domain, type, protocol, 0);
}

int
iou_socket_direct(reactor_t * reactor, int domain, int type, int protocol) {
    ssize_t index = bitset_get(reactor->registered_file_bits);
    if (index < 0)
        return iou_socket(reactor, domain, type, protocol);

    int result = IOU(reactor, socket_direct, domain, type & ~SOCK_CLOEXEC, protocol, index, 0);

    if (result < 0) {
        bitset_put(reactor->registered_file_bits, index);
        return result;
    }

    return FD_BUILD(index);
}

static void
_iou_spawn_trampoline(sigjmp_buf *buf, pid_t *pid, const posix_spawnattr_t *attrs, int stdin_fd, int stdout_fd, const char *command, const char *argv[]) {
    posix_spawn_file_actions_t file_actions;

    TRY(posix_spawn_file_actions_init, &file_actions);

    if (stdin_fd >= 0) {
        TRY(posix_spawn_file_actions_adddup2, &file_actions, stdin_fd, STDIN_FILENO);
    } else {
        TRY(posix_spawn_file_actions_addclose, &file_actions, STDIN_FILENO);
    }

    if (stdout_fd >= 0) {
        TRY(posix_spawn_file_actions_adddup2, &file_actions, stdout_fd, STDOUT_FILENO);
    } else {
        TRY(posix_spawn_file_actions_addopen, &file_actions, STDOUT_FILENO, "/dev/null", O_WRONLY|O_APPEND, 0666);
    }

    TRY(posix_spawnp, pid, command, &file_actions, attrs, (char * const *)argv, NULL);

    TRY(posix_spawn_file_actions_destroy, &file_actions);

    siglongjmp(*buf, true);
}

pid_t
iou__spawn(reactor_t * reactor, const posix_spawnattr_t *attrs, int to_fd, int from_fd, const char *command, ...) {
    va_list argv;
    va_start(argv, command);
    pid_t pid = iou_spawnv(reactor, attrs, to_fd, from_fd, command, argv);
    va_end(argv);
    return pid;
}

static inline size_t
va_list_size(va_list va) {
    size_t c = 0;
    va_list copy;
    va_copy(copy, va);
    while (va_arg(copy, void*)) ++c;
    va_end(copy);
    return c;
}

pid_t
iou_spawnv(reactor_t * reactor, const posix_spawnattr_t *attrs, int to_fd, int from_fd, const char *command, va_list args) {
    assert(reactor);

    stack_t stack = reactor->stack;

    if (attrs)
        if (!(attrs = stack_memcpy(&stack, attrs, sizeof(*attrs), alignof(*attrs))))
            return -ENOMEM;

    size_t argc = 1 + va_list_size(args);
    const char **argv = stack_array(&stack, const char*, argc + 1);
    if (!argv)
        return -ENOMEM;

    if (!(argv[0] = stack_strcpy(&stack, command)))
        return -ENOMEM;

    for (int i = 1 ; i < argc; ++i)
        if (!(argv[i] = stack_strcpy(&stack, va_arg(args, char*))))
            return -ENOMEM;

    assert(NULL == va_arg(args, char*));
    argv[argc] = NULL;

    int real_to_fd = (to_fd >= 0 && FD_FIXED(to_fd)) ? iou_fd_install_no_cloexec(reactor, to_fd) : to_fd;
    int real_from_fd = (from_fd >= 0 && FD_FIXED(from_fd)) ? iou_fd_install_no_cloexec(reactor, from_fd) : from_fd;

    pid_t pid = -1;
    sigjmp_buf todo;
    if (!sigsetjmp(todo, false)) {
        ucontext_t uc;
        TRY(getcontext, &uc);
        uc.uc_stack = stack;
        uc.uc_link = NULL;
        makecontext(&uc, (void(*)())_iou_spawn_trampoline, 7,
            &todo,
            &pid, attrs,
            to_fd, from_fd,
            command, argv);
        setcontext(&uc);
    }

    if (real_to_fd != to_fd) iou_close_fast(reactor, real_to_fd);
    if (real_from_fd != from_fd) iou_close_fast(reactor, real_from_fd);

    return pid;
}

ssize_t
iou_splice(reactor_t * reactor, int fd_in, int fd_out, size_t len) {
    return iou_splice_offset(reactor, fd_in, NULL, fd_out, NULL, len, SPLICE_F_MOVE);
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
iou_splice_offset(reactor_t * reactor, int fd_in, off_t *off_in, int fd_out, off_t *off_out, size_t len, int flags) {
    assert(!(flags & SPLICE_F_FD_IN_FIXED));
    ssize_t result = IOU_FLAGS(reactor, FD_FLAGS(fd_out), splice,
        FD_VALUE(fd_in), off_in ? *off_in : -1,
        FD_VALUE(fd_out), off_out ? *off_out : -1,
        len, FD_FIXED(fd_in) ? (flags | SPLICE_F_FD_IN_FIXED) : (flags & ~SPLICE_F_FD_IN_FIXED));

    if (result > 0) {
        if (off_in) *off_in += result;
        if (off_out) *off_out += result;
    }

    return result;
}

int
iou_statx(reactor_t * reactor, const char *pathname, struct statx *statxbuf) {
    return iou_statxat(reactor, AT_FDCWD, pathname, 0, STATX_BASIC_STATS, statxbuf);
}

int
iou_statxat(reactor_t * reactor, int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf) {
    VALGRIND_CHECK_MEM_IS_ADDRESSABLE(statxbuf, sizeof *statxbuf);
    VALGRIND_MAKE_MEM_UNDEFINED(statxbuf, sizeof *statxbuf);

    int result = IOU_FLAGS(reactor, DIRFD_FLAGS(dirfd), statx, DIRFD_VALUE(dirfd), pathname, flags | AT_EMPTY_PATH, mask, statxbuf);

    if (0 == result)
        VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(statxbuf, sizeof *statxbuf);

    return result;
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
    VALGRIND_CHECK_STRING(path1);
    VALGRIND_CHECK_STRING(path2);

    return IOU_FLAGS(reactor, FD_FLAGS(fd), symlinkat, path1, FD_VALUE(fd), path2);
}

int
iou_sync_file_range(reactor_t * reactor, int fd, off_t offset, off_t nbytes, bool wait) {
    const unsigned int flags_no_wait = SYNC_FILE_RANGE_WRITE;
    const unsigned int flags_yes_wait = SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;

    IOU_FLAGS(reactor, FD_FLAGS(fd), sync_file_range, FD_VALUE(fd), offset, nbytes, wait ? flags_yes_wait : flags_no_wait);
}

ssize_t
iou_tee(reactor_t * reactor, int fd_in, int fd_out, size_t len) {
    return IOU_FLAGS(reactor, FD_FLAGS(fd_out), tee, FD_VALUE(fd_in), FD_VALUE(fd_out), len,
        FD_FIXED(fd_in) ? SPLICE_F_FD_IN_FIXED : 0);
}

int
iou_unlink(reactor_t * reactor, const char *pathname) {
    return iou_unlinkat(reactor, AT_FDCWD, pathname);
}

int
iou_unlinkat(reactor_t * reactor, int dirfd, const char *pathname) {
    VALGRIND_CHECK_STRING(pathname);

    return IOU_FLAGS(reactor, DIRFD_FLAGS(dirfd), unlinkat, DIRFD_VALUE(dirfd), pathname, 0);
}

int
iou_vprintf(reactor_t * reactor, int fd, const char *format, va_list args) {
    assert(reactor);

    va_list copy;
    va_copy(copy, args);

    char buffer[256];
    int result = vsnprintf(buffer, sizeof buffer, format, args);

    if (result >= sizeof buffer) {
        _iou_cookie_t cookie = {
            .reactor = reactor,
            .fd = fd,
            .offset = -1,
        };
        static const cookie_io_functions_t cookie_io = {
            .write = _iou_cookie_write,
        };
        FILE *file = fopencookie(&cookie, "w", cookie_io);
        result = vfprintf(file, format, copy);
        fflush(file);
        fclose(file);
    } else if (result > 0) {
        result = iou_write(reactor, fd, buffer, result);
    }

    va_end(copy);
    return result;
}

int
iou_vscanf(reactor_t * reactor, int fd, const char *format, va_list args) {
    assert(reactor);

    va_list copy;
    va_copy(copy, args);

    _iou_cookie_t cookie = {
        .reactor = reactor,
        .fd = fd,
        .offset = -1,
    };
    static const cookie_io_functions_t cookie_io = {
        .read = _iou_cookie_read,
    };
    FILE *file = fopencookie(&cookie, "r", cookie_io);
    TRY(setvbuf, file, NULL, _IONBF, 0);
    int result = vfscanf(file, format, copy);
    fclose(file);

    va_end(copy);
    return result;
}

int
iou_waitid(reactor_t * reactor, idtype_t idtype, id_t id, siginfo_t *infop, int options) {
    VALGRIND_CHECK_MEM_IS_ADDRESSABLE(infop, sizeof *infop);

    int result = IOU(reactor, waitid, idtype, id, infop, options, 0);

    if (0 == result)
        VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(infop, sizeof *infop);

    return result;
}

pid_t
iou_waitpid(reactor_t * reactor, pid_t pid, int *wstatus, int options) {
    idtype_t type = (WAIT_ANY == pid) ? P_ALL : (WAIT_MYPGRP == pid) ? P_PGID : P_PID;
    id_t id = (WAIT_ANY != pid || WAIT_MYPGRP != pid) ? pid : 0;

    siginfo_t infop = { };
    int result = iou_waitid(reactor, type, id, &infop, options | WEXITED);
    if (result < 0)
        return result;

    if (wstatus && infop.si_pid)
    switch (infop.si_code) {
    case CLD_EXITED:	*wstatus = W_EXITCODE(infop.si_status, 0); break;
    case CLD_KILLED:	*wstatus = W_EXITCODE(0, infop.si_status); break;
    case CLD_DUMPED:	*wstatus = W_EXITCODE(0, infop.si_status) | WCOREFLAG ; break;
    case CLD_STOPPED:	*wstatus = W_STOPCODE(infop.si_status); break;
    case CLD_TRAPPED:	*wstatus = W_STOPCODE(infop.si_status); break;
    case CLD_CONTINUED:	*wstatus = __W_CONTINUED; break;
    default: abort();
    }

    return infop.si_pid;
}

ssize_t
iou_write(reactor_t * reactor, int fildes, const void *buf, size_t nbytes) {
    ssize_t out = 0;

    VALGRIND_CHECK_MEM_IS_DEFINED(buf, nbytes);

    while (out < nbytes) {
        ssize_t n = iou_pwrite(reactor, fildes, buf + out, nbytes - out, -1);
        if (n <= 0) switch(n) {
        case 0: return out;
        case -EINTR: continue;
        case -EAGAIN:
            if (!iou_yield(reactor))
                iou_poll_out(reactor, fildes, timespec_block);
            continue;
        default: return n;
        }
        out += n;
    }

    return out;
}

bool
iou_yield(reactor_t * reactor) {
    if (!reactor_runnable(reactor))
        return false;

    IOU(reactor, nop);
    return true;
}

//
