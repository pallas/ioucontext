// SPDX-License-Identifier: MIT
#include "eventcount.h"

#include "operations.h"
#include "timespec.h"

void
iou_eventcount(iou_eventcount_t * eventcount) {
    atomic_init(&eventcount->ticket, 0);
}

iou_eventcount_ticket_t
iou_eventcount_ticket(reactor_t * reactor, const iou_eventcount_t * eventcount) {
    return atomic_load_explicit(&eventcount->ticket, memory_order_relaxed);
}

iou_eventcount_ticket_t
iou_eventcount_wait(reactor_t * reactor, iou_eventcount_t * eventcount, const iou_eventcount_ticket_t want) {
    iou_eventcount_ticket_t have = atomic_load_explicit(&eventcount->ticket, memory_order_relaxed);
    if (!(want & 1) && have == want && !atomic_compare_exchange_weak_explicit(
        &eventcount->ticket, &have, have | 1,
        memory_order_relaxed, memory_order_relaxed
        )) {
        /* stale ticket */
    } else if ((want | 1) == (have | 1)) do {
        iou_futex_wait32(reactor, (uint32_t*)&eventcount->ticket, want | 1, timespec_block);
    } while ((want | 1) == (have = atomic_load_explicit(&eventcount->ticket, memory_order_relaxed)));
    return have;
}

void
iou_eventcount_wake(reactor_t * reactor, iou_eventcount_t * eventcount, int n) {
    iou_eventcount_ticket_t ticket = atomic_load_explicit(&eventcount->ticket, memory_order_relaxed);
    while (!atomic_compare_exchange_weak_explicit(
        &eventcount->ticket, &ticket, (ticket & ~1) + 2,
        memory_order_release, memory_order_relaxed
        ) && (ticket & 1)) { }
    if (n < INT_MAX || (ticket & 1))
        iou_futex_wake32_fast(reactor, (uint32_t*)&eventcount->ticket, n);
}

void
iou_eventcount_wake_all(reactor_t * reactor, iou_eventcount_t * eventcount) {
    iou_eventcount_wake(reactor, eventcount, INT_MAX);
}

void
iou_eventcount_wake_one(reactor_t * reactor, iou_eventcount_t * eventcount) {
    iou_eventcount_wake(reactor, eventcount, 1);
}

//
