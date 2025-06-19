// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_MUTEX_H
#define IOUCONTEXT_MUTEX_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct reactor_s reactor_t;

typedef _Atomic uint32_t iou_mutex_value_t;
typedef struct iou_mutex_s {
    iou_mutex_value_t value;
} iou_mutex_t;

void iou_mutex_build(reactor_t *, iou_mutex_t *);
bool iou_mutex_knock(reactor_t *, iou_mutex_t *);
void iou_mutex_enter(reactor_t *, iou_mutex_t *);
bool iou_mutex_taken(reactor_t *, const iou_mutex_t *);
void iou_mutex_leave(reactor_t *, iou_mutex_t *);

typedef struct iou_mootex_s {
    iou_mutex_t mutex;
    atomic_uintptr_t owner;
    unsigned depth;
} iou_mootex_t;

void iou_mootex_build(reactor_t *, iou_mootex_t *);
bool iou_mootex_knock(reactor_t *, iou_mootex_t *);
void iou_mootex_enter(reactor_t *, iou_mootex_t *);
bool iou_mootex_taken(reactor_t *, const iou_mootex_t *);
bool iou_mootex_owner(reactor_t *, const iou_mootex_t *);
void iou_mootex_leave(reactor_t *, iou_mootex_t *);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_MUTEX_H
