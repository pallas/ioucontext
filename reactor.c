// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include "reactor-internal.h"

#include "macros-internal.h"
#include "stack.h"
#include "todo_sigjmp.h"

#include <assert.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>

static void make_reactor_key();
static tss_t reactor_key;
static once_flag reactor_key_once_flag = ONCE_FLAG_INIT;

static thread_local reactor_t reactor_local;

static void
reactor_set(reactor_t * reactor) {
    struct io_uring_params params = {0};
    params.flags |= IORING_SETUP_SQPOLL;
    params.flags |= IORING_SETUP_SUBMIT_ALL;
    params.flags |= IORING_SETUP_SINGLE_ISSUER;
    params.flags |= IORING_SETUP_NO_SQARRAY;

    params.sq_thread_idle = 100;

    cpu_set_t cpu_set;
    CPU_ZERO_S(sizeof(cpu_set_t), &cpu_set);
    TRY(sched_getaffinity, 0, sizeof(cpu_set_t), &cpu_set);
    if (1==CPU_COUNT_S(sizeof(cpu_set_t), &cpu_set)) {
        for (int i = 0 ; i < CPU_SETSIZE ; ++i) {
            if (CPU_ISSET_S(i, sizeof(cpu_set_t), &cpu_set)) {
                params.flags |= IORING_SETUP_SQ_AFF;
                params.sq_thread_cpu = i;
                break;
            }
        }
    }

    static _Atomic int fd = -1;
    if (fd >= 0) {
        params.flags |= IORING_SETUP_ATTACH_WQ;
        params.wq_fd = fd;
    }

    const char * env_queue_depth = getenv("IOUCONTEXT_QUEUE_DEPTH");
    reactor->queue_depth = env_queue_depth ? strtoul(env_queue_depth, NULL, 0) : 1024;

    TRY(io_uring_queue_init_params, reactor->queue_depth, &reactor->ring, &params);
    TRY(io_uring_register_ring_fd, &reactor->ring);
    TRY(io_uring_ring_dontfork, &reactor->ring);

    if (params.features & IORING_FEAT_NO_IOWAIT)
        TRY(io_uring_set_iowait, &reactor->ring, false);

    jump_queue_reset(&reactor->todos);
    reactor->runner = NULL;
    reactor->stack = stack_dofork(stack_get_signal());
    reactor->stack_cache = NULL;
    reactor->cookie = NULL;
    reactor->cookie_eat = NULL;
    reactor->sqes = reactor->tare = reactor->cqes = reactor->reserved = 0;
    reactor->current = NULL;
    reactor->urandomfd = -1;

    if (fd < 0)
        fd = reactor->ring.ring_fd;
}

reactor_t *
reactor_get() {
    call_once(&reactor_key_once_flag, make_reactor_key);

    reactor_t * reactor = tss_get(reactor_key);

    if (!reactor) {
        reactor = &reactor_local;
        reactor_set(reactor);
        EXPECT(thrd_success, tss_set, reactor_key, reactor);
        assert(reactor == tss_get(reactor_key));
    }

    return reactor;
}

__attribute__((constructor)) static void reactor_construct(void) { volatile reactor_t *reactor = reactor_get(); }

static void
reactor_put(reactor_t * reactor) {
    assert(!reactor_running(reactor));
    assert(!reactor->current);
    if (reactor->urandomfd >= 0)
        close(reactor->urandomfd);
    if (reactor->cookie_eat)
        reactor->cookie_eat(reactor->cookie);
    io_uring_unregister_ring_fd(&reactor->ring);
    io_uring_queue_exit(&reactor->ring);
    stack_put(reactor->stack);
    while (reactor->stack_cache)
        stack_put(reactor_stack_get(reactor));
}

void *
reactor_cookie(reactor_t * reactor) {
    assert(reactor);
    return reactor->cookie;
}

bool
reactor_cookie_eat(reactor_t * reactor) {
    assert(reactor);

    if (!reactor->cookie_eat)
        return false;

    reactor->cookie_eat(reactor->cookie);

    reactor->cookie = NULL;
    reactor->cookie_eat = NULL;

    return true;
}

void *
reactor_cookie_jar(reactor_t * reactor, void *cookie, reactor_cookie_eat_t eat) {
    assert(reactor);
    void *stale = reactor->cookie;
    reactor->cookie = cookie;
    reactor->cookie_eat = eat;
    return stale;
}

static void
make_reactor_key() {
    EXPECT(thrd_success, tss_create, &reactor_key, (void(*)())reactor_put);
    VALGRIND_HG_DISABLE_CHECKING(&reactor_key, sizeof reactor_key);
}

static unsigned
reactor_flush(reactor_t * reactor) {
    unsigned base = reactor->cqes;

    static const size_t n_cqes = 64;
    struct io_uring_cqe *cqes[n_cqes];
    unsigned n;
    do {
        if ((n = io_uring_peek_batch_cqe(&reactor->ring, cqes, n_cqes))) {
            reactor->cqes += n;
            for (unsigned i = 0 ; i < n ; ++i) {
                jump_chain_t * todo = (jump_chain_t*)io_uring_cqe_get_data(cqes[i]);
                if (!todo)
                    continue;

                if (!(cqes[i]->flags & IORING_CQE_F_NOTIF) || cqes[i]->res < 0)
                    todo->result = cqes[i]->res;

                if (cqes[i]->flags & IORING_CQE_F_MORE) {
                    ++reactor->sqes;
                    ++reactor->tare;
                } else {
                    jump_queue_enqueue(&reactor->todos, todo);
                }
            }
            io_uring_cq_advance(&reactor->ring, n);
        }
    } while (n == n_cqes);

    return reactor->cqes - base;
}

static const unsigned submit_threshold = 16;

static unsigned
reactor_cqes(reactor_t * reactor) {
    assert(reactor);

    if (jump_queue_empty(&reactor->todos)) {
        reactor->tare = reactor->sqes;
        io_uring_submit_and_wait(&reactor->ring, 1);
    } else if (reactor->sqes - reactor->tare >= submit_threshold) {
        reactor->tare = reactor->sqes;
        io_uring_submit(&reactor->ring);
    }

    return reactor_flush(reactor);
}

static bool
reactor__will_block(reactor_t * reactor, size_t n) {
    if (reactor->reserved < n) {
        const unsigned sqes = io_uring_sq_space_left(&reactor->ring);
        assert(reactor->reserved <= sqes);
        reactor->reserved = sqes;
    }

    return reactor->reserved < n;
}

static unsigned
reactor__inflight(const reactor_t * reactor) {
    return reactor->sqes - reactor->cqes;
}

static void
reactor__enter_core(reactor_t * reactor) {
    while (reactor_runnable(reactor)) {

        if (reactor->sqes - reactor->tare >= submit_threshold) {
            reactor->tare = reactor->sqes;
            io_uring_submit(&reactor->ring);
        }

        while (!jump_queue_empty(&reactor->todos) && !reactor__will_block(reactor, 1)) {
            jump_chain_t * todo = jump_queue_dequeue(&reactor->todos);
            if (todo->fiber == reactor->current)
                return;
            jump_invoke(todo, reactor);
        }

        if (reactor__inflight(reactor))
            reactor_cqes(reactor);
        else if (reactor->tare != reactor->sqes) {
            reactor->tare = reactor->sqes;
            io_uring_submit(&reactor->ring);
        }
    }

    if (reactor->runner) {
        reactor->current = NULL;
        siglongjmp(*reactor->runner, true);
    }

    abort();
}

void
reactor_enter_core(reactor_t * reactor) {
    reactor__enter_core(reactor);
}

static __attribute__((noipa)) void
reactor_sigjmp_core(reactor_t * reactor, todo_sigjmp_t * todo) {
    if (!sigsetjmp(*make_todo_sigjmp(todo, reactor->current), false))
        reactor__enter_core(reactor);

    assert(todo->jump.fiber == reactor->current);
}

static struct io_uring_sqe *
reactor__sqe_or_fail(reactor_t * reactor) {
    assert(reactor);
    ++reactor->sqes;

    if (UNLIKELY(!reactor->reserved))
        abort();

    --reactor->reserved;
    return io_uring_get_sqe(&reactor->ring);
}

int
reactor_promise(reactor_t * reactor, struct io_uring_sqe * sqe) {
    todo_sigjmp_t todo;
    io_uring_sqe_set_data(sqe, (void*)&todo.jump);
    reactor_sigjmp_core(reactor, &todo);
    return todo.jump.result;
}

int
reactor_promise_nonchalant(reactor_t * reactor, struct io_uring_sqe * sqe) {
    assert(reactor->reserved >= 1);

    todo_sigjmp_t todo;
    io_uring_sqe_set_data(sqe, (void*)&todo.jump);
    sqe->flags |= IOSQE_IO_LINK;

    struct __kernel_timespec kts = { .tv_nsec = 32767 };

    sqe = reactor__sqe_or_fail(reactor);
    io_uring_prep_link_timeout(sqe, &kts, 0
        | IORING_TIMEOUT_BOOTTIME
        );
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, NULL);

    reactor_sigjmp_core(reactor, &todo);
    return todo.jump.result;
}

int
reactor_promise_impatient(reactor_t * reactor, struct io_uring_sqe * sqe, struct timespec when) {
    assert(reactor->reserved >= 1);

    todo_sigjmp_t todo;
    io_uring_sqe_set_data(sqe, (void*)&todo.jump);
    sqe->flags |= IOSQE_IO_LINK;

    when = normalize_timespec(when);
    struct __kernel_timespec kts = {
        .tv_sec = when.tv_sec,
        .tv_nsec = when.tv_nsec,
    };

    sqe = reactor__sqe_or_fail(reactor);
    io_uring_prep_link_timeout(sqe, &kts, 0
        | IORING_TIMEOUT_ABS
        | IORING_TIMEOUT_BOOTTIME
        );
    io_uring_sqe_set_flags(sqe, 0);
    io_uring_sqe_set_data(sqe, NULL);

    reactor_sigjmp_core(reactor, &todo);
    return todo.jump.result;
}

void
reactor_future_fake(reactor_t * reactor, struct io_uring_sqe * sqe) {
    io_uring_sqe_set_data(sqe, NULL);
}

void
reactor_park(reactor_t * reactor, jump_chain_t ** jump) {
    todo_sigjmp_t todo;
    *jump = &todo.jump;
    reactor_sigjmp_core(reactor, &todo);
}

void
reactor_schedule(reactor_t * reactor, jump_chain_t * todo) {
    assert(reactor);
    assert(todo->function);
    assert(!todo->next);

    if (!reactor__will_block(reactor, 1)) {
        struct io_uring_sqe * sqe = reactor__sqe_or_fail(reactor);
        io_uring_prep_nop(sqe);
        io_uring_sqe_set_flags(sqe, 0);
        io_uring_sqe_set_data(sqe, (void*)todo);
    } else {
        jump_queue_enqueue(&reactor->todos, todo);
    }
}

static __attribute__((noipa)) void
reactor_defer(reactor_t * reactor) {
    todo_sigjmp_t todo;
    if (!sigsetjmp(*make_todo_sigjmp(&todo, reactor->current), false)) {
        jump_queue_enqueue(&reactor->todos, &todo.jump);
        reactor__enter_core(reactor);
    }
    assert(todo.jump.fiber == reactor->current);
}

static void
reactor__reserve_sqes(reactor_t * reactor, size_t n) {
    assert(reactor);

    if (UNLIKELY(reactor->queue_depth < n))
        abort();

    while (reactor__will_block(reactor, n)) {
        if (!jump_queue_empty(&reactor->todos)) {
            reactor_defer(reactor);
        } else if (!reactor__inflight(reactor) && !reactor->reserved) {
            TRY(io_uring_sqring_wait, &reactor->ring);
        } else if (io_uring_cq_ready(&reactor->ring)) {
            reactor_flush(reactor);
        } else if (reactor->tare != reactor->sqes) {
            reactor->tare = reactor->sqes;
            TRY(io_uring_submit_and_get_events, &reactor->ring);
        } else {
            TRY(io_uring_get_events, &reactor->ring);
        }
    }

    assert(io_uring_sq_space_left(&reactor->ring) >= n);
    assert(reactor->reserved >= n);
}

void
reactor_reserve_sqes(reactor_t * reactor, size_t n) {
    reactor__reserve_sqes(reactor, n);
}


struct io_uring_sqe *
reactor_sqe(reactor_t * reactor) {
    assert(reactor);
    ++reactor->sqes;

    if (reactor__will_block(reactor, 1))
        reactor__reserve_sqes(reactor, 1);

    --reactor->reserved;
    return io_uring_get_sqe(&reactor->ring);
}

bool reactor_running(const reactor_t * reactor) { return reactor->runner; }
bool reactor_runnable(const reactor_t * reactor) { return reactor__inflight(reactor) > 0 || !jump_queue_empty(&reactor->todos); }
uintptr_t reactor_current(const reactor_t * reactor) { return (uintptr_t)reactor->current ?: (uintptr_t)reactor; }

typedef struct reactor_stack_cache_s {
    stack_t stack;
    reactor_stack_cache_t *next;
} reactor_stack_cache_t;

bool
reactor_stack_has(reactor_t * reactor) {
    return reactor->stack_cache;
}

stack_t
reactor_stack_get(reactor_t * reactor) {
    assert(reactor_stack_has(reactor));
    stack_t stack = reactor->stack_cache->stack;
    reactor->stack_cache = reactor->stack_cache->next;
    VALGRIND_MAKE_MEM_UNDEFINED(stack.ss_sp, stack.ss_size);
    return stack;
}

void
reactor_stack_put(reactor_t * reactor, stack_t stack) {
    reactor_stack_cache_t * entry = (reactor_stack_cache_t *)stack.ss_sp;
    stack_clear(stack);
    VALGRIND_MAKE_MEM_NOACCESS(entry + 1, stack.ss_size - sizeof *entry);
    entry->stack = stack;
    entry->next = reactor->stack_cache;
    reactor->stack_cache = entry;
}

void
reactor_run(reactor_t * reactor) {
    assert(reactor);
    assert(!reactor_running(reactor));
    assert(!reactor->current);

    if (reactor_runnable(reactor)) {
        sigjmp_buf runner;
        reactor->runner = &runner;

        if (!sigsetjmp(*reactor->runner, false))
            reactor__enter_core(reactor);

        reactor->runner = NULL;
    }

    assert(!reactor_running(reactor));
    assert(!reactor->current);
}

//
