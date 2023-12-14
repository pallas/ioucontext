// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_OPERATIONS_H
#define IOUCONTEXT_OPERATIONS_H

#include "reactor.h"
#include "timespec.h"

#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

int io_accept(reactor_t *, int fd, struct sockaddr *addr, socklen_t *addrlen);
void io_barrier(reactor_t *);
void io_cancel_fd_all(reactor_t *, int fd);
void io_cancel_fd_any(reactor_t *, int fd);
int io_close(reactor_t *, int fd);
int io_connect(reactor_t *, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int io_exchange(reactor_t *, const char *oldpath, const char *newpath);
int io_exchangeat(reactor_t *, int dirfd, const char *oldpath, const char *newpath);
int io_fadvise(reactor_t *, int fd, off_t offset, off_t len, int advice);
int io_fallocate(reactor_t *, int fd, int mode, off_t offset, off_t len);
int io_fdatasync(reactor_t *, int fd);
int io_fgetxattr(reactor_t *, int fd, const char *name, void *value, size_t size);
void io_flush(reactor_t *);
int io_fsetxattr(reactor_t *, int fd, const char *name, const void *value, size_t size, int flags);
int io_fsync(reactor_t *, int fd);
int io_getxattr(reactor_t *, const char *path, const char *name, void *value, size_t size);
int io_link(reactor_t *, const char *oldpath, const char *newpath);
int io_linkat(reactor_t *, int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
int io_madvise(reactor_t *, void *addr, size_t len, int advice);
int io_mkdir(reactor_t *, const char *pathname, mode_t mode);
int io_mkdirat(reactor_t *, int dirfd, const char *pathname, mode_t mode);
int io_open(reactor_t *, const char *pathname, int flags, mode_t mode);
int io_openat(reactor_t *, int dirfd, const char *pathname, int flags, mode_t mode);
bool io_poll_hup(reactor_t *, int fd, const struct timespec delta);
bool io_poll_in(reactor_t *, int fd, const struct timespec delta);
bool io_poll_out(reactor_t *, int fd, const struct timespec delta);
int io_printf(reactor_t *, int fd, const char *format, ...);
ssize_t io_read(reactor_t *, int fildes, void *buf, size_t nbyte);
ssize_t io_read_offset(reactor_t *, int fildes, void *buf, size_t nbyte, off_t offset);
ssize_t io_recv(reactor_t *, int socket, void *buffer, size_t length, int flags);
ssize_t io_recvfrom(reactor_t *, int socket, void *buffer, size_t length, int flags, struct sockaddr *address, socklen_t address_len);
int io_rename(reactor_t *, const char *oldpath, const char *newpath);
int io_rename_noreplace(reactor_t *, const char *oldpath, const char *newpath);
int io_renameat(reactor_t *, int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
int io_rmdir(reactor_t * reactor, const char *pathname);
int io_rmdirat(reactor_t *, int dirfd, const char *pathname);
ssize_t io_send(reactor_t *, int socket, const void *buffer, size_t length, int flags);
ssize_t io_sendto(reactor_t *, int socket, const void *message, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t dest_len);
int io_setxattr(reactor_t *, const char *path, const char *name, const void *value, size_t size, int flags);
int io_shutdown(reactor_t *, int sockfd);
int io_shutdown_read(reactor_t *, int sockfd);
int io_shutdown_write(reactor_t *, int sockfd);
struct timespec io_sleep(reactor_t *, const struct timespec delta);
bool io_sleep_absolute(reactor_t *, const struct timespec when);
int io_socket(reactor_t *, int domain, int type, int protocol);
ssize_t io_splice(reactor_t *, int fd_in, int fd_out, size_t len);
ssize_t io_splice_all(reactor_t *, int fd_in, int fd_out, size_t len);
ssize_t io_splice_offset(reactor_t *, int fd_in, off_t *off_in, int fd_out, off_t *off_out, size_t len);
int io_statx(reactor_t *, const char *pathname, struct statx *statxbuf);
int io_statxat(reactor_t *, int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf);
int io_statxfd(reactor_t *, int fd, struct statx *statxbuf);
int io_symlink(reactor_t *, const char *path1, const char *path2);
int io_symlinkat(reactor_t *, const char *path1, int fd, const char *path2);
int io_sync_file_range(reactor_t *, int fd, off_t offset, off_t nbytes, bool wait);
ssize_t io_tee(reactor_t *, int fd_in, int fd_out, size_t len);
int io_unlink(reactor_t *, const char *pathname);
int io_unlinkat(reactor_t *, int dirfd, const char *pathname);
int io_vprintf(reactor_t *, int fd, const char *format, va_list args);
ssize_t io_write(reactor_t *, int fildes, const void *buf, size_t nbyte);
ssize_t io_write_offset(reactor_t *, int fildes, const void *buf, size_t nbyte, off_t offset);
void io_yield(reactor_t *);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_OPERATIONS_H
