// SPDX-License-Identifier: MIT
#include "queue.h"

#include "operations.h"

#include <assert.h>

enum { iou_queue__mask = iou_queue__size - 1 };

void
iou_queue(iou_queue_t * queue) {
    assert(0 == (iou_queue__size & iou_queue__mask));
    assert(iou_queue__size == sizeof(queue->epochs)/sizeof(*queue->epochs));
    assert(iou_queue__size == sizeof(queue->items)/sizeof(*queue->items));
    for (iou_queue_index_t i = 0 ; i < iou_queue__size ; ++i)
        atomic_init(&queue->epochs[i], i);
    atomic_init(&queue->enqueue, 0);
    atomic_init(&queue->dequeue, 0);
}

static inline iou_queue_index_t
iou_queue__get_epoch(const iou_queue_t * queue, iou_queue_index_t i) {
    return atomic_load_explicit(&queue->epochs[i & iou_queue__mask], memory_order_acquire);
}

static inline void
iou_queue__set_epoch(iou_queue_t * queue, iou_queue_index_t i, iou_queue_index_t x) {
    atomic_store_explicit(&queue->epochs[i & iou_queue__mask], x, memory_order_release);
}

static inline bool
iou_queue__underflow(const iou_queue_t * queue, iou_queue_index_t i) {
    return (iou_queue_index_t)(iou_queue__get_epoch(queue, i) - (i + 1)) > iou_queue__mask;
}

static inline bool
iou_queue__overflow(const iou_queue_t * queue, iou_queue_index_t i) {
    return (iou_queue_index_t)(iou_queue__get_epoch(queue, i) - i) > iou_queue__mask;
}

bool
iou_queue_empty(reactor_t * reactor, const iou_queue_t * queue) {
    iou_queue_index_t i = atomic_load_explicit(&queue->dequeue, memory_order_relaxed);
    return iou_queue__underflow(queue, i);
}

void
iou_queue_enqueue(reactor_t * reactor, iou_queue_t * queue, iou_queue_item_t item) {
    iou_queue_index_t i;
    do {
        iou_eventcount_ticket_t ticket = iou_eventcount_ticket(reactor, &queue->drain);
        i = atomic_load_explicit(&queue->enqueue, memory_order_relaxed);
        while (iou_queue__overflow(queue, i)) {
            ticket = iou_eventcount_wait(reactor, &queue->drain, ticket);
            i = atomic_load_explicit(&queue->enqueue, memory_order_relaxed);
        }
    } while(!atomic_compare_exchange_weak_explicit(
        &queue->enqueue, &i, i + 1,
        memory_order_relaxed, memory_order_relaxed
        ));

    queue->items[i & iou_queue__mask] = item;
    iou_queue__set_epoch(queue, i, i + 1);
    iou_eventcount_wake_one(reactor, &queue->fill);
}

iou_queue_item_t
iou_queue_dequeue(reactor_t * reactor, iou_queue_t * queue) {
    iou_queue_index_t i;
    do {
        iou_eventcount_ticket_t ticket = iou_eventcount_ticket(reactor, &queue->fill);
        i = atomic_load_explicit(&queue->dequeue, memory_order_relaxed);
        while (iou_queue__underflow(queue, i)) {
            ticket = iou_eventcount_wait(reactor, &queue->fill, ticket);
            i = atomic_load_explicit(&queue->dequeue, memory_order_relaxed);
        }
    } while (!atomic_compare_exchange_weak_explicit(
        &queue->dequeue, &i, i + 1,
        memory_order_relaxed, memory_order_relaxed
        ));

    iou_queue_item_t item = queue->items[i & iou_queue__mask];
    iou_queue__set_epoch(queue, i, i + iou_queue__size);
    iou_eventcount_wake_one(reactor, &queue->drain);
    return item;
}

//
