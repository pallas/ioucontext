// SPDX-License-Identifier: MIT
#include "mutex.h"

#include "macros-internal.h"
#include "operations.h"
#include "reactor.h"
#include "timespec.h"

#include <assert.h>

static void
iou_mutex__build(reactor_t * reactor, iou_mutex_t * mutex) {
    atomic_init(&mutex->value, 0);
}

void
iou_mutex_build(reactor_t * reactor, iou_mutex_t * mutex) {
    iou_mutex__build(reactor, mutex);
    VALGRIND_HG_MUTEX_INIT_POST(mutex, 1);
}

static bool
iou_mutex__knock(reactor_t * reactor, iou_mutex_t * mutex) {
    iou_mutex_value_t shadow = 0;
    return atomic_compare_exchange_weak_explicit(
        &mutex->value, &shadow, 1,
        memory_order_acquire, memory_order_relaxed
        );
}

bool
iou_mutex_knock(reactor_t * reactor, iou_mutex_t * mutex) {
    VALGRIND_HG_MUTEX_LOCK_PRE(mutex, 1);
    bool locked = iou_mutex__knock(reactor, mutex);
    if (locked)
        VALGRIND_HG_MUTEX_LOCK_POST(mutex);
    return locked;
}

static void
iou_mutex__enter(reactor_t * reactor, iou_mutex_t * mutex) {
    if (iou_mutex__knock(reactor, mutex))
        return;

    if (iou_yield(reactor) && iou_mutex__knock(reactor, mutex))
        return;

    while (0 != atomic_exchange_explicit(&mutex->value, -1, memory_order_acquire)) do {
        iou_futex_wait32(reactor, (uint32_t*)&mutex->value, -1, timespec_block);
    } while (-1 == atomic_load_explicit(&mutex->value, memory_order_relaxed));

    assert(iou_mutex_taken(reactor, mutex));
}

void
iou_mutex_enter(reactor_t * reactor, iou_mutex_t * mutex) {
    VALGRIND_HG_MUTEX_LOCK_PRE(mutex, 0);
    iou_mutex__enter(reactor, mutex);
    VALGRIND_HG_MUTEX_LOCK_POST(mutex);
}

bool
iou_mutex_taken(reactor_t * reactor, const iou_mutex_t * mutex) {
    return 0 != atomic_load_explicit(&mutex->value, memory_order_relaxed);
}

static void
iou_mutex__leave(reactor_t * reactor, iou_mutex_t * mutex) {
    assert(iou_mutex_taken(reactor, mutex));
    if (-1 == atomic_exchange_explicit(&mutex->value, 0, memory_order_release))
        iou_futex_wake32_fast(reactor, (uint32_t*)&mutex->value, 1);
}

void
iou_mutex_leave(reactor_t * reactor, iou_mutex_t * mutex) {
    VALGRIND_HG_MUTEX_UNLOCK_PRE(mutex);
    iou_mutex__leave(reactor, mutex);
    VALGRIND_HG_MUTEX_UNLOCK_POST(mutex);
}


void
iou_mootex_build(reactor_t * reactor, iou_mootex_t * mootex) {
    iou_mutex__build(reactor, &mootex->mutex);
    VALGRIND_HG_MUTEX_INIT_POST(mootex, 1);
    VALGRIND_HG_DISABLE_CHECKING(&mootex->owner, sizeof mootex->owner);
    VALGRIND_HG_DISABLE_CHECKING(&mootex->depth, sizeof mootex->depth);
    atomic_init(&mootex->owner, 0);
    mootex->depth = 0;
}

bool
iou_mootex_knock(reactor_t * reactor, iou_mootex_t * mootex) {
    VALGRIND_HG_MUTEX_LOCK_PRE(mootex, 1);
    const uintptr_t whoami = reactor_current(reactor);
    if (whoami == atomic_load_explicit(&mootex->owner, memory_order_relaxed)) {
        ++mootex->depth;
        VALGRIND_HG_MUTEX_LOCK_POST(mootex);
        return true;
    }

    if (iou_mutex__knock(reactor, &mootex->mutex)) {
        assert(0 == mootex->depth);
        mootex->depth = 1;
        assert(!atomic_load_explicit(&mootex->owner, memory_order_relaxed));
        atomic_store_explicit(&mootex->owner, whoami, memory_order_relaxed);
        VALGRIND_HG_MUTEX_LOCK_POST(mootex);
        return true;
    }

    return false;
}

void
iou_mootex_enter(reactor_t * reactor, iou_mootex_t * mootex) {
    VALGRIND_HG_MUTEX_LOCK_PRE(mootex, 0);
    const uintptr_t whoami = reactor_current(reactor);
    if (whoami == atomic_load_explicit(&mootex->owner, memory_order_relaxed)) {
        ++mootex->depth;
    } else {
        iou_mutex__enter(reactor, &mootex->mutex);
        assert(0 == mootex->depth);
        mootex->depth = 1;
        assert(!atomic_load_explicit(&mootex->owner, memory_order_relaxed));
        atomic_store_explicit(&mootex->owner, whoami, memory_order_relaxed);
    }
    VALGRIND_HG_MUTEX_LOCK_POST(mootex);
}

bool
iou_mootex_taken(reactor_t * reactor, const iou_mootex_t * mootex) {
    return iou_mutex_taken(reactor, &mootex->mutex);
}

bool
iou_mootex_owner(reactor_t * reactor, const iou_mootex_t * mootex) {
    const uintptr_t whoami = reactor_current(reactor);
    return whoami == atomic_load_explicit(&mootex->owner, memory_order_relaxed);
}

void
iou_mootex_leave(reactor_t * reactor, iou_mootex_t * mootex) {
    VALGRIND_HG_MUTEX_UNLOCK_PRE(mootex);
    const uintptr_t whoami = reactor_current(reactor);
    if (UNLIKELY(whoami != atomic_load_explicit(&mootex->owner, memory_order_relaxed)))
        abort();
    if (!--mootex->depth) {
        atomic_store_explicit(&mootex->owner, 0, memory_order_relaxed);
        iou_mutex__leave(reactor, &mootex->mutex);
    }
    VALGRIND_HG_MUTEX_UNLOCK_POST(mootex);
}

//
