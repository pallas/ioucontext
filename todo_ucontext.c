// SPDX-License-Identifier: MIT
#include "todo_ucontext.h"

#include "macros-internal.h"

#include <assert.h>
#include <string.h>

static void
ucontext_done(jump_argument argument) {
    todo_ucontext_t * todo = CONTAINER_OF(argument, todo_ucontext_t, jump);
    setcontext(&todo->uc);
}

struct ucontext_t *
make_todo_ucontext(todo_ucontext_t * todo, fiber_t * fiber) {
    explicit_bzero(&todo->uc, sizeof todo->uc);
    TRY(getcontext, &todo->uc);
    todo->jump = (jump_chain_t) {
        .function = ucontext_done,
        .fiber = fiber,
    };
    assert(todo->jump.next == NULL);
    return &todo->uc;
}

//
