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
    fiber_t fiber = *f;
    assert(!fiber.todo.jump.next);
    stack_put(fiber.full_stack);
    reactor_enter_core(fiber.reactor);
    abort();
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
    fiber->bounce.uc_stack = reactor->stack;
    fiber->bounce.uc_link = NULL;
    makecontext(&fiber->bounce, (void(*)())fiber_put, 1, fiber);

    ucontext_t * main_context = make_todo_ucontext(&fiber->todo);
    main_context->uc_stack = main_stack;
    main_context->uc_link = &fiber->bounce;

    reactor_schedule(reactor, &fiber->todo.jump);

    return main_context;
}

//
