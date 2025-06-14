// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_OPERATIONS_H
#define IOUCONTEXT_OPERATIONS_H

#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

struct epoll_event;
struct iovec;
struct siginfo_t;
struct sockaddr;
struct statx;
struct timespec;

typedef struct reactor_s reactor_t;

int iou_accept(reactor_t *, int fd, struct sockaddr *addr, socklen_t *addrlen);
void iou_barrier(reactor_t *);
int iou_bind(reactor_t *, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
void iou_cancel_fd_all(reactor_t *, int fd);
void iou_cancel_fd_any(reactor_t *, int fd);
int iou_close(reactor_t *, int fd);
void iou_close_fast(reactor_t *, int fd);
int iou_connect(reactor_t *, int sockfd, const struct sockaddr *addr, socklen_t addrlen, const struct timespec delta);
int iou_discard(reactor_t *, int fd, off_t offset, off_t len);
int iou_epoll_add(reactor_t *, int epfd, int fd, struct epoll_event *event);
int iou_epoll_ctl(reactor_t *, int epfd, int op, int fd, struct epoll_event *event);
int iou_epoll_del(reactor_t *, int epfd, int fd);
int iou_epoll_mod(reactor_t *, int epfd, int fd, struct epoll_event *event);
int iou_epoll_set(reactor_t *, int epfd, int fd, struct epoll_event *event);
int iou_exchange(reactor_t *, const char *oldpath, const char *newpath);
int iou_exchangeat(reactor_t *, int dirfd, const char *oldpath, const char *newpath);
bool iou_exists(reactor_t *, const char *pathname);
int iou_fadvise(reactor_t *, int fd, off_t offset, off_t len, int advice);
int iou_fallocate(reactor_t *, int fd, int mode, off_t offset, off_t len);
ssize_t iou_fd_size(reactor_t *, int fd);
int iou_fdatasync(reactor_t *, int fd);
int iou_fgetxattr(reactor_t *, int fd, const char *name, void *value, size_t size);
void iou_flush(reactor_t *);
int iou_fsetxattr(reactor_t *, int fd, const char *name, const void *value, size_t size, int flags);
int iou_fsync(reactor_t *, int fd);
int iou_ftruncate(reactor_t *, int fildes, off_t length);
int iou_getsockopt(reactor_t *, int socket, int level, int option_name, void *option_value, socklen_t *option_len);
int iou_getsockopt_int(reactor_t *, int socket, int level, int option_name);
int iou_getxattr(reactor_t *, const char *path, const char *name, void *value, size_t size);
int iou_link(reactor_t *, const char *oldpath, const char *newpath);
int iou_linkat(reactor_t *, int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
int iou_listen(reactor_t *, int sockfd, int backlog);
int iou_madvise(reactor_t *, void *addr, size_t len, int advice);
int iou_mkdir(reactor_t *, const char *pathname, mode_t mode);
int iou_mkdirat(reactor_t *, int dirfd, const char *pathname, mode_t mode);
int iou_open(reactor_t *, const char *pathname, int flags, mode_t mode);
int iou_openat(reactor_t *, int dirfd, const char *pathname, int flags, mode_t mode);
bool iou_poll_hup(reactor_t *, int fd, const struct timespec delta);
bool iou_poll_in(reactor_t *, int fd, const struct timespec delta);
bool iou_poll_out(reactor_t *, int fd, const struct timespec delta);
ssize_t iou_pread(reactor_t *, int fildes, void *buf, size_t nbyte, off_t offset);
ssize_t iou_preadv(reactor_t *, int fildes, const struct iovec *iov, int iovcnt, off_t offset, int flags);
int iou_printf(reactor_t *, int fd, const char *format, ...) __attribute__ ((format (printf, 3, 4)));
ssize_t iou_pwrite(reactor_t *, int fildes, const void *buf, size_t nbyte, off_t offset);
ssize_t iou_pwritev(reactor_t *, int fildes, const struct iovec *iov, int iovcnt, off_t offset, int flags);
ssize_t iou_read(reactor_t *, int fildes, void *buf, size_t nbyte);
ssize_t iou_recv(reactor_t *, int socket, void *buffer, size_t length, int flags);
ssize_t iou_recvfrom(reactor_t *, int socket, void *buffer, size_t length, int flags, struct sockaddr *address, socklen_t address_len);
int iou_rename(reactor_t *, const char *oldpath, const char *newpath);
int iou_rename_noreplace(reactor_t *, const char *oldpath, const char *newpath);
int iou_renameat(reactor_t *, int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
int iou_rmdir(reactor_t * reactor, const char *pathname);
int iou_rmdirat(reactor_t *, int dirfd, const char *pathname);

typedef uintptr_t iou_semaphore_t;
iou_semaphore_t iou_semaphore_get(reactor_t *, uint64_t value);
int iou_semaphore_wait(reactor_t *, iou_semaphore_t, const struct timespec delta);
void iou_semaphore_post(reactor_t *, iou_semaphore_t);
void iou_semaphore_put(reactor_t *, iou_semaphore_t);

ssize_t iou_send(reactor_t *, int socket, const void *buffer, size_t length, int flags);
ssize_t iou_sendto(reactor_t *, int socket, const void *message, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t dest_len);
int iou_setsockopt(reactor_t *, int socket, int level, int option_name, const void *option_value, socklen_t option_len);
int iou_setsockopt_int(reactor_t *, int socket, int level, int option_name, const int option_value);
int iou_setxattr(reactor_t *, const char *path, const char *name, const void *value, size_t size, int flags);
int iou_shutdown(reactor_t *, int sockfd);
int iou_shutdown_read(reactor_t *, int sockfd);
int iou_shutdown_write(reactor_t *, int sockfd);
int iou_siocinq(reactor_t *, int socket);
int iou_siocoutq(reactor_t *, int socket);
struct timespec iou_sleep(reactor_t *, const struct timespec delta);
bool iou_sleep_absolute(reactor_t *, const struct timespec when);
int iou_socket(reactor_t *, int domain, int type, int protocol);
pid_t iou__spawn(reactor_t *, const posix_spawnattr_t *attrs, int to_fd, int from_fd, const char *command, ...);
#define iou_spawn(...) iou__spawn(__VA_ARGS__, NULL)
pid_t iou_spawnv(reactor_t *, const posix_spawnattr_t *attrs, int to_fd, int from_fd, const char *command, va_list args);
ssize_t iou_splice(reactor_t *, int fd_in, int fd_out, size_t len);
ssize_t iou_splice_all(reactor_t *, int fd_in, int fd_out, size_t len);
ssize_t iou_splice_offset(reactor_t *, int fd_in, off_t *off_in, int fd_out, off_t *off_out, size_t len);
int iou_statx(reactor_t *, const char *pathname, struct statx *statxbuf);
int iou_statxat(reactor_t *, int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf);
int iou_statxfd(reactor_t *, int fd, struct statx *statxbuf);
int iou_symlink(reactor_t *, const char *path1, const char *path2);
int iou_symlinkat(reactor_t *, const char *path1, int fd, const char *path2);
int iou_sync_file_range(reactor_t *, int fd, off_t offset, off_t nbytes, bool wait);
ssize_t iou_tee(reactor_t *, int fd_in, int fd_out, size_t len);
int iou_unlink(reactor_t *, const char *pathname);
int iou_unlinkat(reactor_t *, int dirfd, const char *pathname);
int iou_vprintf(reactor_t *, int fd, const char *format, va_list args);
int iou_waitid(reactor_t *, idtype_t idtype, id_t id, siginfo_t *infop, int options);
pid_t iou_waitpid(reactor_t *, pid_t pid, int *wstatus, int options);
ssize_t iou_write(reactor_t *, int fildes, const void *buf, size_t nbyte);
void iou_yield(reactor_t *);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_OPERATIONS_H
