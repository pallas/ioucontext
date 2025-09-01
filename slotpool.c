// SPDX-License-Identifier: MIT
#include "slotpool.h"

#include "macros-internal.h"
#include "operations.h"
#include "timespec.h"

#include <assert.h>
#include <limits.h>
#include <linux/futex.h>

void
iou_slotpool(iou_slotpool_t slotpool[], size_t n) {
    for (size_t i = 0 ; i < n ; ++i)
        atomic_init(&slotpool[i].value, ~0);
}

static inline iou_slotpool_value_t
iou_slotpool__bit(size_t index) {
    const static iou_slotpool_value_t iou_slotpool__one = 1;
    assert(index < iou_slotpool_slots);
    return iou_slotpool__one << index;
}

size_t
iou_slotpool_try(reactor_t * reactor, iou_slotpool_t slotpool[], size_t n) {
    assert(n);
    size_t i_limit = 4;
    while (i_limit --> 0) {
        for (size_t i = 0 ; i < n ; ++i) {
            size_t v_limit = 4;
            iou_slotpool_value_t value = atomic_load_explicit(&slotpool[i].value, memory_order_relaxed);
            while (value && v_limit --> 0) {
                size_t index = __builtin_ctz(value);
                assert(index < iou_slotpool_slots);
                iou_slotpool_value_t bit = iou_slotpool__bit(index);
                value = atomic_fetch_and_explicit(&slotpool[i].value, ~bit, memory_order_relaxed);
                if (bit & value) {
                    atomic_thread_fence(memory_order_acquire);
                    return index + (i * iou_slotpool_slots);
                }
            }
        }
    }
    return n * iou_slotpool_slots;
}

size_t
iou_slotpool_get(reactor_t * reactor, iou_slotpool_t slotpool[], size_t n) {
    assert(n);
    size_t j = 0;
    struct futex_waitv futexv[n];
    do {
        size_t slot = iou_slotpool_try(reactor, slotpool, n);
        if (slot < n * iou_slotpool_slots)
            return slot;

        for ( ; j < n ; ++j)
            futexv[j] = (struct futex_waitv){
                .val = 0,
                .uaddr = (uintptr_t)&slotpool[j].value,
                .flags = FUTEX_PRIVATE_FLAG | FUTEX2_SIZE_U32,
            };
        iou_futex_waitv(reactor, futexv, n, timespec_block);
    } while (true);
}

size_t
iou_slotpool_has(reactor_t * reactor, const iou_slotpool_t slotpool[], size_t n) {
    size_t has = 0;
    for (size_t i = 0 ; i < n ; ++i)
        has += __builtin_popcountll(atomic_load_explicit(&slotpool[i].value, memory_order_relaxed));
    return has;
}

void
iou_slotpool_put(reactor_t * reactor, iou_slotpool_t slotpool[], size_t n, size_t slot) {
    if (UNLIKELY(slot >= n * iou_slotpool_slots))
        abort();

    size_t i = slot / iou_slotpool_slots;
    iou_slotpool_value_t bit = iou_slotpool__bit(slot % iou_slotpool_slots);
    iou_slotpool_value_t value = atomic_fetch_or_explicit(&slotpool[i].value, bit, memory_order_release);

    if (UNLIKELY(value & bit))
        abort();

    iou_futex_wake32_fast(reactor, (uint32_t*)&slotpool[i].value, 1);
}

//
