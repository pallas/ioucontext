// SPDX-License-Identifier: MIT
#include "semaphore.h"

#include "macros-internal.h"
#include "operations.h"
#include "timespec.h"

#include <assert.h>

void
iou_semaphore_init(reactor_t * reactor, iou_semaphore_t * semaphore, const iou_semaphore_value_t value) {
    atomic_init(&semaphore->value, value);
    VALGRIND_HG_SEM_INIT_POST(&semaphore->value, value);
}

void
iou_semaphore_wait(reactor_t * reactor, iou_semaphore_t * semaphore) {
    const static iou_semaphore_value_t n = 1;
    iou_semaphore_value_t value = atomic_load_explicit(&semaphore->value, memory_order_relaxed);
    do {
        while (value < n) {
            iou_futex_wait32(reactor, (uint32_t*)&semaphore->value, value, timespec_block);
            value = atomic_load_explicit(&semaphore->value, memory_order_relaxed);
        }
    } while (!atomic_compare_exchange_weak_explicit(
        &semaphore->value, &value, value - n,
        memory_order_acquire, memory_order_relaxed
        ));
    VALGRIND_HG_SEM_WAIT_POST(&semaphore->value);
}

void
iou_semaphore_post(reactor_t * reactor, iou_semaphore_t * semaphore) {
    const static iou_semaphore_value_t n = 1;
    VALGRIND_HG_SEM_POST_PRE(&semaphore->value);
    iou_semaphore_value_t value = atomic_load_explicit(&semaphore->value, memory_order_relaxed);
    do {
        if (UNLIKELY(ADD_OVERFLOW_P(value, n)))
            abort();
    } while (!atomic_compare_exchange_weak_explicit(
        &semaphore->value, &value, value + n,
        memory_order_release, memory_order_relaxed
        ));
    iou_futex_wake32_fast(reactor, (uint32_t*)&semaphore->value, n);
}

//
