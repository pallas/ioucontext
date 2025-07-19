// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_SEMAPHORE_H
#define IOUCONTEXT_SEMAPHORE_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct reactor_s reactor_t;

typedef uint32_t iou_semaphore_value_t;
typedef struct iou_semaphore_s {
    _Atomic iou_semaphore_value_t value;
} iou_semaphore_t;

void iou_semaphore(iou_semaphore_t *, const iou_semaphore_value_t);
void iou_semaphore_wait(reactor_t *, iou_semaphore_t *);
void iou_semaphore_post(reactor_t *, iou_semaphore_t *);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_SEMAPHORE_H
