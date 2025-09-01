// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_SLOTPOOL_H
#define IOUCONTEXT_SLOTPOOL_H

#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct reactor_s reactor_t;

typedef uint32_t iou_slotpool_value_t;
enum { iou_slotpool_slots = sizeof(iou_slotpool_value_t) * CHAR_BIT };

typedef struct iou_slotpool_t {
    _Atomic iou_slotpool_value_t value;
} iou_slotpool_t;

void iou_slotpool(iou_slotpool_t slotpool[], size_t n);
size_t iou_slotpool_try(reactor_t *, iou_slotpool_t slotpool[], size_t n);
size_t iou_slotpool_get(reactor_t *, iou_slotpool_t slotpool[], size_t n);
size_t iou_slotpool_has(reactor_t *, const iou_slotpool_t slotpool[], size_t n);
void iou_slotpool_put(reactor_t *, iou_slotpool_t slotpool[], size_t n, size_t index);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_SLOTPOOL_H
