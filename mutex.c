// SPDX-License-Identifier: MIT
#include "mutex.h"

#include "macros.h"
#include "operations.h"
#include "reactor.h"
#include "timespec.h"

#include <assert.h>

void
iou_mutex_build(reactor_t * reactor, iou_mutex_t * mutex) {
    atomic_init(&mutex->value, 0);
}

bool
iou_mutex_knock(reactor_t * reactor, iou_mutex_t * mutex) {
    iou_mutex_value_t shadow = 0;
    return atomic_compare_exchange_weak_explicit(
        &mutex->value, &shadow, 1,
        memory_order_acquire, memory_order_relaxed
        ) && 0 == shadow;
}

void
iou_mutex_enter(reactor_t * reactor, iou_mutex_t * mutex) {
    if (iou_mutex_knock(reactor, mutex))
        return;

    iou_yield(reactor);

    if (!iou_mutex_knock(reactor, mutex))
    while (0 != atomic_exchange_explicit(&mutex->value, -1, memory_order_acquire))
        iou_futex_wait32(reactor, (uint32_t*)&mutex->value, -1, timespec_block);

    assert(iou_mutex_taken(reactor, mutex));
}

bool
iou_mutex_taken(reactor_t * reactor, const iou_mutex_t * mutex) {
    return 0 != atomic_load_explicit(&mutex->value, memory_order_relaxed);
}

void
iou_mutex_leave(reactor_t * reactor, iou_mutex_t * mutex) {
    assert(iou_mutex_taken(reactor, mutex));
    if (-1 == atomic_exchange_explicit(&mutex->value, 0, memory_order_release))
        iou_futex_wake32_fast(reactor, (uint32_t*)&mutex->value, 1);
}


void
iou_mootex_build(reactor_t * reactor, iou_mootex_t * mootex) {
    iou_mutex_build(reactor, &mootex->mutex);
    atomic_init(&mootex->owner, 0);
    mootex->depth = 0;
}

bool
iou_mootex_knock(reactor_t * reactor, iou_mootex_t * mootex) {
    uintptr_t whoami = reactor_current(reactor);
    if (whoami == atomic_load_explicit(&mootex->owner, memory_order_relaxed)) {
        ++mootex->depth;
        return true;
    }

    if (iou_mutex_knock(reactor, &mootex->mutex)) {
        assert(0 == mootex->depth);
        mootex->depth = 1;
        assert(!atomic_load_explicit(&mootex->owner, memory_order_relaxed));
        atomic_store_explicit(&mootex->owner, whoami, memory_order_relaxed);
        return true;
    }

    return false;
}

void
iou_mootex_enter(reactor_t * reactor, iou_mootex_t * mootex) {
    uintptr_t whoami = reactor_current(reactor);
    if (whoami == atomic_load_explicit(&mootex->owner, memory_order_relaxed)) {
        ++mootex->depth;
    } else {
        iou_mutex_enter(reactor, &mootex->mutex);
        assert(0 == mootex->depth);
        mootex->depth = 1;
        assert(!atomic_load_explicit(&mootex->owner, memory_order_relaxed));
        atomic_store_explicit(&mootex->owner, whoami, memory_order_relaxed);
    }
}

bool
iou_mootex_taken(reactor_t * reactor, const iou_mootex_t * mootex) {
    return iou_mutex_taken(reactor, &mootex->mutex);
}

void
iou_mootex_leave(reactor_t * reactor, iou_mootex_t * mootex) {
    uintptr_t whoami = reactor_current(reactor);
    if (UNLIKELY(whoami != atomic_load_explicit(&mootex->owner, memory_order_relaxed)))
        abort();
    if (!--mootex->depth) {
        atomic_store_explicit(&mootex->owner, 0, memory_order_relaxed);
        iou_mutex_leave(reactor, &mootex->mutex);
    }
}

//
