// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_TODO_SIGJMP_H
#define IOUCONTEXT_TODO_SIGJMP_H
#include "defortified_setjmp.h"

#include "jump_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct todo_sigjmp_s {
    jump_chain_t jump;
    sigjmp_buf buf;
} todo_sigjmp_t;

#ifndef HIDDEN
#define HIDDEN __attribute__((visibility("hidden")))
#endif//HIDDEN

HIDDEN sigjmp_buf * make_todo_sigjmp(todo_sigjmp_t * todo, fiber_t * fiber);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_TODO_SIGJMP_H
