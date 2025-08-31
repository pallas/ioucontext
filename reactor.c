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
    params.flags |= IORING_SETUP_SINGLE_ISSUER;

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

    const char * env_queue_depth = getenv("IOUCONTEXT_QUEUE_DEPTH");
    reactor->queue_depth = env_queue_depth ? strtol(env_queue_depth, NULL, 0) : 1024;

    TRY(io_uring_queue_init_params, reactor->queue_depth, &reactor->ring, &params);
    TRY(io_uring_register_ring_fd, &reactor->ring);
    TRY(io_uring_ring_dontfork, &reactor->ring);

    jump_queue_reset(&reactor->todos);
    reactor->runner = NULL;
    reactor->stack = stack_dofork(stack_get_signal());
    reactor->stack_cache = NULL;
    reactor->cookie = NULL;
    reactor->cookie_eat = NULL;
    reactor->sqes = reactor->cqes = reactor->reserved = 0;
    reactor->current = NULL;
    reactor->pivot = NULL;
    reactor->urandomfd = -1;
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

static struct jump_chain_s * const pivoting = (struct jump_chain_s *)~(uintptr_t)0;

void
reactor__reactor_synchronize(reactor_t * reactor) {
    assert(!reactor->pivot);
    reactor->pivot = pivoting;
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

    unsigned head;
    struct io_uring_cqe * cqe;
    io_uring_for_each_cqe(&reactor->ring, head, cqe) {
        ++reactor->cqes;
        jump_chain_t * todo;
        if (todo = (jump_chain_t*)io_uring_cqe_get_data(cqe)) {
            if (!(cqe->flags & IORING_CQE_F_NOTIF) || cqe->res < 0)
                todo->result = cqe->res;

            if (cqe->flags & IORING_CQE_F_MORE) {
                ++reactor->sqes;
            } else if (reactor->pivot == todo) {
                reactor->pivot = NULL;
                jump_queue_requeue(&reactor->todos, todo);
            } else {
                jump_queue_enqueue(&reactor->todos, todo);
            }
        }
    }

    unsigned delta = reactor->cqes - base;
    if (delta > 0)
        io_uring_cq_advance(&reactor->ring, delta);

    return delta;
}

static unsigned
reactor_cqes(reactor_t * reactor) {
    assert(reactor);
    assert(!reactor->pivot);

    io_uring_submit_and_wait(&reactor->ring, !!jump_queue_empty(&reactor->todos));

    unsigned delta = reactor_flush(reactor);

    if (!jump_queue_empty(&reactor->todos))
        jump_invoke(jump_queue_dequeue(&reactor->todos), reactor);

    return delta;
}

void
reactor_enter_core(reactor_t * reactor) {
    while (reactor_runnable(reactor)) {

        while (reactor->pivot) {
            TRY(io_uring_submit_and_get_events, &reactor->ring);
            reactor_flush(reactor);
        }

        while (!jump_queue_empty(&reactor->todos) && !reactor_will_block(reactor, 1))
            jump_invoke(jump_queue_dequeue(&reactor->todos), reactor);

        if (reactor_inflight(reactor))
            reactor_cqes(reactor);
    }

    if (reactor->runner) {
        reactor->current = NULL;
        siglongjmp(*reactor->runner, true);
    }
}

int
reactor_promise(reactor_t * reactor, struct io_uring_sqe * sqe) {
    todo_sigjmp_t todo;
    if (!sigsetjmp(*make_todo_sigjmp(&todo, reactor->current), false)) {
        io_uring_sqe_set_data(sqe, (void*)&todo.jump);
        if (reactor->pivot == pivoting)
            reactor->pivot = &todo.jump;
        reactor_enter_core(reactor);
    }
    return jump_result(&todo.jump);
}

int
reactor_promise_nonchalant(reactor_t * reactor, struct io_uring_sqe * sqe) {
    assert(reactor->reserved >= 1);

    todo_sigjmp_t todo;
    if (!sigsetjmp(*make_todo_sigjmp(&todo, reactor->current), false)) {
        io_uring_sqe_set_data(sqe, (void*)&todo.jump);
        io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);

        struct __kernel_timespec kts = { .tv_nsec = 32767 };

        sqe = reactor_sqe(reactor);
        io_uring_prep_link_timeout(sqe, &kts, 0
            | IORING_TIMEOUT_BOOTTIME
            );
        io_uring_sqe_set_data(sqe, NULL);

        if (reactor->pivot == pivoting)
            reactor->pivot = &todo.jump;
        reactor_enter_core(reactor);
    }
    return jump_result(&todo.jump);
}

int
reactor_promise_impatient(reactor_t * reactor, struct io_uring_sqe * sqe, struct timespec when) {
    assert(reactor->reserved >= 1);

    todo_sigjmp_t todo;
    if (!sigsetjmp(*make_todo_sigjmp(&todo, reactor->current), false)) {
        io_uring_sqe_set_data(sqe, (void*)&todo.jump);
        io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);

        when = normalize_timespec(when);
        struct __kernel_timespec kts = {
            .tv_sec = when.tv_sec,
            .tv_nsec = when.tv_nsec,
        };

        sqe = reactor_sqe(reactor);
        io_uring_prep_link_timeout(sqe, &kts, 0
            | IORING_TIMEOUT_ABS
            | IORING_TIMEOUT_BOOTTIME
            );
        io_uring_sqe_set_data(sqe, NULL);

        if (reactor->pivot == pivoting)
            reactor->pivot = &todo.jump;
        reactor_enter_core(reactor);
    }
    return jump_result(&todo.jump);
}

void
reactor_future_fake(reactor_t * reactor, struct io_uring_sqe * sqe) {
    io_uring_sqe_set_data(sqe, NULL);
    if (reactor->pivot == pivoting)
        reactor->pivot = NULL;
}

void
reactor_park(reactor_t * reactor, jump_chain_t ** jump) {
    todo_sigjmp_t todo;
    if (!sigsetjmp(*make_todo_sigjmp(&todo, reactor->current), false)) {
        *jump = &todo.jump;
        reactor_enter_core(reactor);
    }
}

void
reactor_schedule(reactor_t * reactor, jump_chain_t * todo) {
    assert(reactor);
    assert(todo->function);
    assert(!todo->next);

    if (!reactor_will_block(reactor, 1)) {
        struct io_uring_sqe * sqe = reactor_sqe(reactor);
        io_uring_prep_nop(sqe);
        io_uring_sqe_set_data(sqe, (void*)todo);
    } else {
        jump_queue_enqueue(&reactor->todos, todo);
    }
}

static void
reactor_defer(reactor_t * reactor) {
    todo_sigjmp_t todo;
    if (!sigsetjmp(*make_todo_sigjmp(&todo, reactor->current), false)) {
        jump_queue_enqueue(&reactor->todos, &todo.jump);
        reactor_enter_core(reactor);
    }
}

static void
reactor_refer(reactor_t * reactor) {
    todo_sigjmp_t todo;
    if (!sigsetjmp(*make_todo_sigjmp(&todo, reactor->current), false)) {
        jump_queue_requeue(&reactor->todos, &todo.jump);
        reactor_enter_core(reactor);
    }
}

void
reactor_reserve_sqes(reactor_t * reactor, size_t n) {
    assert(reactor);

    if (UNLIKELY(reactor->queue_depth < n))
        abort();

    if (reactor->pivot) {
        while (reactor_will_block(reactor, n)) {
            reactor_flush(reactor);
            TRY(io_uring_sqring_wait, &reactor->ring);
        }
    } else {
        if (!jump_queue_empty(&reactor->todos) || io_uring_cq_has_overflow(&reactor->ring))
            reactor_defer(reactor);

        while (reactor_will_block(reactor, n)) {
            if (io_uring_cq_ready(&reactor->ring))
                reactor_refer(reactor);

            TRY(io_uring_submit_and_get_events, &reactor->ring);

            if (!io_uring_cq_ready(&reactor->ring))
                TRY(io_uring_sqring_wait, &reactor->ring);
        }
    }

    assert(io_uring_sq_space_left(&reactor->ring) >= n);
    assert(reactor->reserved >= n);
}

bool
reactor_will_block(reactor_t * reactor, size_t n) {
    if (reactor->reserved < n) {
        unsigned sqes = io_uring_sq_space_left(&reactor->ring);
        if (reactor->reserved < sqes)
            reactor->reserved = sqes;
    }
    return reactor->reserved < n;
}

struct io_uring_sqe *
reactor_sqe(reactor_t * reactor) {
    assert(reactor);
    ++reactor->sqes;

    if (!reactor->reserved)
        reactor_reserve_sqes(reactor, 1);

    --reactor->reserved;
    return io_uring_get_sqe(&reactor->ring);
}

bool reactor_running(const reactor_t * reactor) { return reactor->runner; }
unsigned reactor_inflight(const reactor_t * reactor) { return reactor->sqes - reactor->cqes; }
bool reactor_runnable(const reactor_t * reactor) { return reactor_inflight(reactor) > 0 || !jump_queue_empty(&reactor->todos); }
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
            reactor_enter_core(reactor);

        reactor->runner = NULL;
    }

    assert(!reactor_running(reactor));
    assert(!reactor->current);
}

//
