// SPDX-License-Identifier: MIT
#include "todo_null.h"

#include <assert.h>

void
make_todo_null(todo_null_t * todo) {
    todo->jump = (jump_chain_t) { };
    assert(todo->jump.next == NULL);
}

//
