// SPDX-License-Identifier: MIT
#include "todo_sigjmp.h"

#include <assert.h>
#include <string.h>

static void
sigjmp_done(void * buf) {
    siglongjmp(*(sigjmp_buf *)buf, true);
}

sigjmp_buf *
make_todo_sigjmp(todo_sigjmp_t * todo, fiber_t * fiber) {
    explicit_bzero(&todo->buf, sizeof todo->buf);
    todo->jump = (jump_chain_t) {
        .fun = sigjmp_done,
        .arg = &todo->buf,
        .fib = fiber,
    };
    assert(todo->jump.next == NULL);
    return &todo->buf;
}

//
