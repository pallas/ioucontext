// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_JUMP_QUEUE_H
#define IOUCONTEXT_JUMP_QUEUE_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fiber_s fiber_t;
typedef void * jump_argument;
typedef void (*jump_function)(jump_argument);

typedef struct jump_chain_s {
    struct jump_chain_s * next;
    jump_function fun;
    jump_argument arg;
    fiber_t *fib;
} jump_chain_t;

void jump_invoke(jump_chain_t *);

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
