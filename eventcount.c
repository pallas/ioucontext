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
    return atomic_load_explicit(&eventcount->ticket, memory_order_acquire);
}

iou_eventcount_ticket_t
iou_eventcount_wait(reactor_t * reactor, iou_eventcount_t * eventcount, const iou_eventcount_ticket_t ticket) {
    while (ticket == atomic_load_explicit(&eventcount->ticket, memory_order_relaxed))
        iou_futex_wait32(reactor, (uint32_t*)&eventcount->ticket, ticket, timespec_block);
    return iou_eventcount_ticket(reactor, eventcount);
}

void
iou_eventcount_wake(reactor_t * reactor, iou_eventcount_t * eventcount, int n) {
    iou_eventcount_ticket_t ticket = atomic_load_explicit(&eventcount->ticket, memory_order_relaxed);
    do {
    } while (!atomic_compare_exchange_weak_explicit(
        &eventcount->ticket, &ticket, ticket + 1,
        memory_order_release, memory_order_relaxed
        ));
    iou_futex_wake32_fast(reactor, (uint32_t*)&eventcount->ticket, n);
}

void
iou_eventcount_wake_all(reactor_t * reactor, iou_eventcount_t * eventcount) {
    iou_eventcount_wake(reactor, eventcount, INT_MAX);
}

//
