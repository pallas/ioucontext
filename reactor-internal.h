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

#ifndef HIDDEN
#define HIDDEN __attribute__((visibility("hidden")))
#endif//HIDDEN

typedef struct bitset_s bitset_t;
typedef struct reactor_stack_cache_s reactor_stack_cache_t;

typedef struct reactor_s {
    struct io_uring ring;
    jump_queue_t todos[3];
    sigjmp_buf *runner;
    stack_t stack;
    reactor_stack_cache_t * stack_cache;
    void *cookie;
    reactor_cookie_eat_t cookie_eat;
    unsigned sqes, tare, cqes;
    unsigned reserved;
    unsigned long queue_depth;
    fiber_t *current;
    int urandomfd;
    bitset_t * registered_file_bits;
} reactor_t;

HIDDEN void reactor_enter_core(reactor_t *);
HIDDEN int reactor_promise(reactor_t *, struct io_uring_sqe *);
HIDDEN int reactor_promise_nonchalant(reactor_t *, struct io_uring_sqe *);
HIDDEN int reactor_promise_impatient(reactor_t *, struct io_uring_sqe *, struct timespec);
HIDDEN void reactor_future_fake(reactor_t *, struct io_uring_sqe *);

HIDDEN struct io_uring_sqe * reactor_sqe(reactor_t * reactor);
HIDDEN void reactor_reserve_sqes(reactor_t *, size_t);

HIDDEN bool reactor_stack_has(reactor_t *);
HIDDEN stack_t reactor_stack_get(reactor_t *);
HIDDEN void reactor_stack_put(reactor_t *, stack_t);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_REACTOR_INTERNAL_H
