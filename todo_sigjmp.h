// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_TODO_SIGJMP_H
#define IOUCONTEXT_TODO_SIGJMP_H

#include "jump_queue.h"

#include <setjmp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    jump_chain_t jump;
    sigjmp_buf buf;
} todo_sigjmp_t;

sigjmp_buf * make_todo_sigjmp(todo_sigjmp_t * todo);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_TODO_SIGJMP_H
