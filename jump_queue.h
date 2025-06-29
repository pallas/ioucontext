// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_JUMP_QUEUE_H
#define IOUCONTEXT_JUMP_QUEUE_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct reactor_s reactor_t;
typedef struct fiber_s fiber_t;
typedef struct jump_chain_s jump_chain_t;
typedef jump_chain_t * jump_argument;
typedef void (*jump_function)(jump_argument);
typedef int jump_result_t;

typedef struct jump_chain_s {
    struct jump_chain_s * next;
    jump_function function;
    fiber_t *fiber;
    jump_result_t result;
} jump_chain_t;

void jump_invoke(jump_chain_t *, reactor_t *);
jump_result_t jump_result(const jump_chain_t *);

typedef struct jump_queue_s {
    jump_chain_t * head;
    jump_chain_t ** tail;
} jump_queue_t;

void jump_queue_reset(jump_queue_t *);
bool jump_queue_empty(const jump_queue_t *);
void jump_queue_chain(jump_queue_t * hither, jump_queue_t * hence);
void jump_queue_enqueue(jump_queue_t *, jump_chain_t *);
jump_chain_t * jump_queue_dequeue(jump_queue_t *);
void jump_queue_requeue(jump_queue_t *, jump_chain_t *);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_JUMP_QUEUE_H
