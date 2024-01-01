// SPDX-License-Identifier: MIT
#include "fiber.h"

#include "reactor-internal.h"
#include "stack.h"
#include "todo_ucontext.h"

#include <assert.h>
#include <string.h>
#include <ucontext.h>

typedef struct fiber_s {
    reactor_t * reactor;
    stack_t full_stack;
    ucontext_t bounce;
    todo_ucontext_t todo;
} fiber_t;

static void
fiber_put(fiber_t *f) {
    reactor_t * reactor = f->reactor;
    stack_t stack = f->full_stack;
    stack_put(stack);
    reactor_enter_core(reactor);
    abort();
}

static void
fiber_bounce(fiber_t *f) {
    assert(!f->todo.jump.next);
    f->bounce.uc_stack = f->reactor->stack;
    f->bounce.uc_link = NULL;
    makecontext(&f->bounce, (void(*)())fiber_put, 1, f);
    setcontext(&f->bounce);
}

ucontext_t *
fiber_get(reactor_t *reactor) {
    assert(reactor);

    stack_t main_stack = stack_get_rlimit();
    stack_t full_stack = main_stack;

    fiber_t * fiber = stack_push(&main_stack, fiber_t);

    fiber->reactor = reactor;
    fiber->full_stack = full_stack;

    explicit_bzero(&fiber->bounce, sizeof fiber->bounce);
    TRY(getcontext, &fiber->bounce);
    fiber->bounce.uc_stack = stack_split(&main_stack, sizeof(fiber), 16);
    fiber->bounce.uc_link = NULL;
    makecontext(&fiber->bounce, (void(*)())fiber_bounce, 1, fiber);

    ucontext_t * main_context = make_todo_ucontext(&fiber->todo);
    main_context->uc_stack = main_stack;
    main_context->uc_link = &fiber->bounce;

    reactor_schedule(reactor, &fiber->todo.jump);

    return main_context;
}

//
