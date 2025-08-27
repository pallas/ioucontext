// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_QUEUE_H
#define IOUCONTEXT_QUEUE_H

#include "eventcount.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct reactor_s reactor_t;

typedef uintptr_t iou_queue_item_t;
typedef uint8_t iou_queue_index_t;

enum { iou_queue__size = 128 };

typedef struct iou_queue_s {
    iou_queue_item_t items[iou_queue__size];
    _Atomic iou_queue_index_t epochs[iou_queue__size];
    iou_eventcount_t fill, drain;
    _Atomic iou_queue_index_t enqueue;
    _Atomic iou_queue_index_t dequeue;
} iou_queue_t;

void iou_queue(iou_queue_t *);
bool iou_queue_empty(reactor_t * reactor, const iou_queue_t *);
void iou_queue_enqueue(reactor_t * reactor, iou_queue_t *, iou_queue_item_t);
iou_queue_item_t iou_queue_dequeue(reactor_t * reactor, iou_queue_t *);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_QUEUE_H
