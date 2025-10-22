// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_TODO_NULL_H
#define IOUCONTEXT_TODO_NULL_H

#include "jump_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HIDDEN
#define HIDDEN __attribute__((visibility("hidden")))
#endif//HIDDEN

typedef struct todo_null_s {
    jump_chain_t jump;
} todo_null_t;

HIDDEN void make_todo_null(todo_null_t * todo);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_TODO_NULL_H
