// SPDX-License-Identifier: MIT
#include "fiber.h"

#include "reactor-internal.h"
#include "stack.h"
#include "todo_ucontext.h"

#include <assert.h>
#include <string.h>
#include <ucontext.h>

typedef struct fiber_s {
    stack_t full_stack;
    ucontext_t bounce;
    todo_ucontext_t todo;
} fiber_t;

static void
fiber_put(fiber_t *fiber, reactor_t *reactor) {
    reactor->current = NULL;
    reactor_stack_put(reactor, fiber->full_stack);
    reactor_enter_core(reactor);
    abort();
}

static void
fiber_bounce(fiber_t *fiber) {
    assert(!fiber->todo.jump.next);
    reactor_t * reactor = reactor_get();
    fiber->bounce.uc_stack = reactor->stack;
    fiber->bounce.uc_link = NULL;
    makecontext(&fiber->bounce, (void(*)())fiber_put, 2, fiber, reactor);
    setcontext(&fiber->bounce);
}

ucontext_t *
__attribute__((malloc, malloc(fiber_put, 1)))
fiber_get(reactor_t *reactor) {
    assert(reactor);

    stack_t main_stack = reactor_stack_has(reactor) ? reactor_stack_get(reactor) : stack_nofork(stack_get_default());
    stack_t full_stack = main_stack;

    fiber_t * fiber = stack_push(&main_stack, fiber_t);

    fiber->full_stack = full_stack;

    explicit_bzero(&fiber->bounce, sizeof fiber->bounce);
    TRY(getcontext, &fiber->bounce);
    fiber->bounce.uc_stack = stack_split(&main_stack, sizeof(fiber) + 2 * sizeof(uintptr_t), 16);
    fiber->bounce.uc_link = NULL;
    makecontext(&fiber->bounce, (void(*)())fiber_bounce, 1, fiber);

    ucontext_t * main_context = make_todo_ucontext(&fiber->todo, fiber);
    main_context->uc_stack = main_stack;
    main_context->uc_link = &fiber->bounce;

    reactor_schedule(reactor, &fiber->todo.jump);

    return main_context;
}

//
