// SPDX-License-Identifier: MIT
#include "todo_sigjmp.h"

#include "macros-internal.h"

#include <assert.h>
#include <string.h>

static void
sigjmp_done(jump_argument argument) {
    todo_sigjmp_t * todo = CONTAINER_OF(argument, todo_sigjmp_t, jump);
    siglongjmp(todo->buf, true);
}

sigjmp_buf *
make_todo_sigjmp(todo_sigjmp_t * todo, fiber_t * fiber) {
    explicit_bzero(&todo->buf, sizeof todo->buf);
    todo->jump = (jump_chain_t) {
        .function = sigjmp_done,
        .fiber = fiber,
    };
    assert(todo->jump.next == NULL);
    return &todo->buf;
}

//
