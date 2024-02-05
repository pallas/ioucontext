// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_MUTEX_H
#define IOUCONTEXT_MUTEX_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fiber_s fiber_t;
typedef struct reactor_s reactor_t;
typedef struct jump_chain_s jump_chain_t;

typedef struct iou_mutex_s {
    int depth;
    fiber_t *owner;
    struct /*jump_chain_s*/ {
        jump_chain_t * head;
        jump_chain_t ** tail;
    } waiters;
} iou_mutex_t;

bool iou_mutex_taken(reactor_t *, const iou_mutex_t *);
bool iou_mutex_probe(reactor_t *, iou_mutex_t *);
void iou_mutex_enter(reactor_t *, iou_mutex_t *);
bool iou_mutex_owner(reactor_t *, const iou_mutex_t *);
void iou_mutex_leave(reactor_t *, iou_mutex_t *);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_MUTEX_H
