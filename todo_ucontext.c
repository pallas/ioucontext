// SPDX-License-Identifier: MIT
#include "todo_ucontext.h"

#include "macros-internal.h"

#include <assert.h>
#include <string.h>

static void
ucontext_done(void * buf) {
    setcontext((struct ucontext_t *)buf);
}

struct ucontext_t *
make_todo_ucontext(todo_ucontext_t * todo, fiber_t * fiber) {
    explicit_bzero(&todo->uc, sizeof todo->uc);
    TRY(getcontext, &todo->uc);
    todo->jump = (jump_chain_t) {
        .fun = ucontext_done,
        .arg = &todo->uc,
        .fib = fiber,
    };
    assert(todo->jump.next == NULL);
    return &todo->uc;
}

//
