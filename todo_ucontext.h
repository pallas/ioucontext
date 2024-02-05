// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_TODO_UCONTEXT_H
#define IOUCONTEXT_TODO_UCONTEXT_H

#include "jump_queue.h"

#include <ucontext.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct todo_ucontext_s {
    jump_chain_t jump;
    struct ucontext_t uc;
} todo_ucontext_t;

struct ucontext_t * make_todo_ucontext(todo_ucontext_t * todo, fiber_t * fiber);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_TODO_UCONTEXT_H
