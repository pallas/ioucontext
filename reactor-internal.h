// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_REACTOR_INTERNAL_H
#define IOUCONTEXT_REACTOR_INTERNAL_H
#include "defortified_setjmp.h"

#include "reactor.h"

#include "jump_queue.h"
#include "timespec.h"

#include <liburing.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef struct reactor_stack_cache_s reactor_stack_cache_t;

typedef struct reactor_s {
    struct io_uring ring;
    jump_queue_t todos;
    sigjmp_buf *runner;
    stack_t stack;
    reactor_stack_cache_t * stack_cache;
    void *cookie;
    reactor_cookie_eat_t cookie_eat;
    int result;
    unsigned sqes, cqes;
    int reserved;
    long int queue_depth;
} reactor_t;

void reactor_enter_core(reactor_t *);
void reactor_promise(reactor_t *, struct io_uring_sqe *);
void reactor_promise_impatient(reactor_t *, struct io_uring_sqe *, struct timespec);
void reactor_future_fake(reactor_t *, struct io_uring_sqe *);

void reactor_schedule(reactor_t *, jump_chain_t *);
struct io_uring_sqe * reactor_sqe(reactor_t * reactor);
void reactor_reserve_sqes(reactor_t *, size_t);
unsigned reactor_inflight(const reactor_t *);
bool reactor_todos(const reactor_t *);

stack_t reactor_stack_get(reactor_t *);
void reactor_stack_put(reactor_t *, stack_t);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_REACTOR_INTERNAL_H
