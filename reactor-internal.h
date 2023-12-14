// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_REACTOR_INTERNAL_H
#define IOUCONTEXT_REACTOR_INTERNAL_H
#include "reactor.h"

#include "jump_queue.h"
#include "timespec.h"

#include <liburing.h>
#include <setjmp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct reactor_s {
    struct io_uring ring;
    jump_queue_t todos;
    sigjmp_buf core;
    stack_t stack;
    void *cookie;
    reactor_cookie_eat_t cookie_eat;
    int result;
    unsigned sqs, cqs;
    int reserved;
    bool running;
} reactor_t;

void reactor_enter_core(reactor_t *);
void reactor_promise(reactor_t *, struct io_uring_sqe *);
void reactor_promise_impatient(reactor_t *, struct io_uring_sqe *, struct timespec);

void reactor_schedule(reactor_t *, jump_chain_t *);
struct io_uring_sqe * reactor_sqe(reactor_t * reactor);
void reactor_reserve_sqes(reactor_t *, size_t);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_REACTOR_INTERNAL_H
