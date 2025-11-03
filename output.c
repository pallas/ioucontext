// SPDX-License-Identifier: MIT
#define _GNU_SOURCE

#include "output.h"

#include "macros-internal.h"
#include "operations.h"
#include "reactor-internal.h"
#include "todo_null.h"

#include <assert.h>
#include <poll.h>

ssize_t
iou__n_output(reactor_t * reactor, int fd_out, const off_t *off_out, size_t n_outs, iou_output_t * const outs[]) {
    size_t total = 0;
    if (RUNNING_ON_VALGRIND) for (size_t i = 0 ; i < n_outs ; ++i) {
        const iou_output_t *out = outs[i];
        switch (out->type) {

        case iou_output_send: {
            VALGRIND_CHECK_MEM_IS_DEFINED(out->info_send.buffer, out->info_send.length);
        } break;

        case iou_output_write: {
            VALGRIND_CHECK_MEM_IS_DEFINED(out->info_write.buffer, out->info_write.length);
        } break;

        default: break;
        };
    }

    const off_t offset = off_out && *off_out >= 0 ? *off_out : -1;

    bool poll_first = false;

    size_t i_outs = 0;
    while (i_outs < n_outs) {
        enum { n_sqes_max = 3 };
        const size_t x_outs = poll_first + (n_outs - i_outs);
        const size_t n = x_outs < n_sqes_max ? x_outs : n_sqes_max;

        todo_null_t todos[n];

        reactor_reserve_sqes(reactor, n);

        for (size_t i = 0 ; i < n ; ++i) {
            struct io_uring_sqe *sqe = reactor_sqe(reactor);

            if (!i && poll_first) {
                io_uring_prep_poll_add(sqe, FD_VALUE(fd_out), POLLOUT);
                io_uring_sqe_set_flags(sqe, FD_FLAGS(fd_out));
                reactor_promise_nothing(reactor, sqe, &todos[i]);
                continue;
            }

            const size_t p = i_outs + i - poll_first;
            const iou_output_t *out = outs[p];
            const bool more = p < n_outs - 1;

            switch (out->type) {

            case iou_output_none: {
                io_uring_prep_nop(sqe);
                io_uring_sqe_set_flags(sqe, 0);
            } break;

            case iou_output_send: {
                if (UNLIKELY(offset >= 0))
                    return total ?: -ENOSYS;
                enum { zero_copy_threshold = 1<<15 };
                if (out->info_send.length >= zero_copy_threshold) {
                    io_uring_prep_send_zc(sqe
                    , FD_VALUE(fd_out)
                    , out->info_send.buffer
                    , out->info_send.length
                    , MSG_NOSIGNAL | MSG_WAITALL
                    | (more ? MSG_MORE : 0)
                    , 0
                    );
                } else {
                    io_uring_prep_send(sqe
                    , FD_VALUE(fd_out)
                    , out->info_send.buffer
                    , out->info_send.length
                    , MSG_NOSIGNAL | MSG_WAITALL
                    | (more ? MSG_MORE : 0)
                    );
                    }
                io_uring_sqe_set_flags(sqe, FD_FLAGS(fd_out));
            } break;

            case iou_output_splice: {
                io_uring_prep_splice(sqe
                , FD_VALUE(out->info_splice.fd_in)
                , (out->info_splice.off_in ? *out->info_splice.off_in : -1)
                , FD_VALUE(fd_out)
                , (offset >= 0 ? offset + total : -1)
                , out->info_splice.length
                , SPLICE_F_MOVE
                | (more ? SPLICE_F_MORE : 0)
                | (FD_FIXED(out->info_splice.fd_in) ? SPLICE_F_FD_IN_FIXED : 0)
                );
                io_uring_sqe_set_flags(sqe, FD_FLAGS(fd_out));
            } break;

            case iou_output_write: {
                io_uring_prep_write(sqe
                , FD_VALUE(fd_out)
                , out->info_write.buffer
                , out->info_write.length
                , (offset >= 0 ? offset + total : -1)
                );
                io_uring_sqe_set_flags(sqe, FD_FLAGS(fd_out));
            } break;

            default: {
                io_uring_prep_nop(sqe);
                io_uring_sqe_set_flags(sqe, 0);
                sqe->nop_flags |= IORING_NOP_INJECT_RESULT;
                sqe->len = -ENOSYS;
            } break;

            }

            if (i+1 < n)
                reactor_promise_nothing(reactor, sqe, &todos[i]);
            else
                todos[i].jump.result = reactor_promise(reactor, sqe);
        }

        for (size_t i = 0 ; i < n ; ++i) {
            ssize_t result = todos[i].jump.result;

            if (!i && poll_first) {
                if (UNLIKELY(result & POLLNVAL)) {
                    abort();
                } else if (UNLIKELY(result & POLLERR)) {
                    return total ?: -iou_getsockopt_int(reactor, fd_out, SOL_SOCKET, SO_ERROR);
                } else if (UNLIKELY(result & POLLHUP)) {
                    return total ?: -EPIPE;
                } else if (LIKELY(result & POLLOUT)) {
                    poll_first = false;
                    continue;
                } else {
                    continue;
                }
            }

            if (-EINTR == result) {
                break;
            } else if (-EAGAIN == result || -EWOULDBLOCK == result || -ECANCELED == result) {
                if (!total)
                    return -EAGAIN;

                poll_first = true;
                break;
            } else if (result < 0) {
                return total ?: result;
            }

            iou_output_t *out = outs[i_outs];
            switch (out->type) {

            case iou_output_none: {
                ++i_outs;
            } break;

            case iou_output_send: {
                if (!result)
                    return total;

                total += result;
                out->info_send.buffer += result;
                assert(result <= out->info_send.length);
                out->info_send.length -= result;
                if (out->info_send.length > 0) {
                    poll_first = true;
                    i = n;
                    continue;
                } else {
                    ++i_outs;
                }
            } break;

            case iou_output_splice: {
                if (!result && !out->info_splice.drain) {
                    return total;
                } else if (!result && out->info_splice.drain) {
                    ++i_outs;
                    i = n;
                    continue;
                }

                total += result;
                if (out->info_splice.off_in && *out->info_splice.off_in >= 0)
                    *out->info_splice.off_in += result;
                assert(result <= out->info_splice.length);
                out->info_splice.length -= result;
                if (out->info_splice.length > 0) {
                    poll_first = true;
                    i = n;
                    continue;
                } else {
                    ++i_outs;
                }
            } break;

            case iou_output_write: {
                if (!result)
                    return total;

                total += result;
                out->info_write.buffer += result;
                assert(result <= out->info_write.length);
                out->info_write.length -= result;
                if (out->info_write.length > 0) {
                    poll_first = true;
                    i = n;
                    continue;
                } else {
                    ++i_outs;
                }
            } break;

            default: abort();
            }
        }
    }

    return total;
}

ssize_t
iou_spaceout(reactor_t * reactor, int fd) {
    struct io_uring_sqe *sqe;
    reactor_reserve_sqes(reactor, 2);

    todo_null_t siocoutq;
    sqe = reactor_sqe(reactor);
    io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_SIOCOUTQ, FD_VALUE(fd), 0, 0, NULL, 0);
    io_uring_sqe_set_flags(sqe, FD_FLAGS(fd));
    reactor_promise_nothing(reactor, sqe, &siocoutq);

    int sndbuf;
    sqe = reactor_sqe(reactor);
    io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_GETSOCKOPT, FD_VALUE(fd), SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);
    io_uring_sqe_set_flags(sqe, FD_FLAGS(fd));

    int result = reactor_promise(reactor, sqe);
    if (result < 0)
        return result;

    VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(&sndbuf, sizeof sndbuf);

    if (siocoutq.jump.result < 0)
        return siocoutq.jump.result;

    if (sndbuf < siocoutq.jump.result)
        return 0;

    return sndbuf - siocoutq.jump.result;
}

//
