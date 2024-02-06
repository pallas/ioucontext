// SPDX-License-Identifier: MIT
#include "mutex.h"

#include "reactor-internal.h"
#include "jump_queue.h"
#include "todo_sigjmp.h"

#include <assert.h>

bool
iou_mutex_taken(reactor_t * reactor, const iou_mutex_t * mutex) {
    assert(!mutex->owner || mutex->depth);
    return mutex->owner;
}

bool
iou_mutex_probe(reactor_t * reactor, iou_mutex_t * mutex) {
    assert(!mutex->owner || mutex->depth);
    fiber_t * whoami = reactor->current ?: (fiber_t*)reactor;

    if (!mutex->owner)
        mutex->owner = whoami;

    return mutex->owner == whoami && ++mutex->depth;
}

void
iou_mutex_enter(reactor_t * reactor, iou_mutex_t * mutex) {
    assert(!mutex->owner || mutex->depth);
    fiber_t * whoami = reactor->current ?: (fiber_t*)reactor;

    while (!iou_mutex_probe(reactor, mutex)) {
        todo_sigjmp_t todo;
        if (!sigsetjmp(*make_todo_sigjmp(&todo, reactor->current), false)) {
            jump_queue_enqueue((jump_queue_t*)&mutex->waiters, &todo.jump);
            reactor_enter_core(reactor);
        }
    }
    assert(mutex->owner == whoami);
}

bool
iou_mutex_owner(reactor_t * reactor, const iou_mutex_t * mutex) {
    assert(!mutex->owner || mutex->depth);
    fiber_t * whoami = reactor->current ?: (fiber_t*)reactor;
    return mutex->owner == whoami;
}

void
iou_mutex_leave(reactor_t * reactor, iou_mutex_t * mutex) {
    assert(mutex->depth);
    fiber_t * whoami = reactor->current ?: (fiber_t*)reactor;
    assert(mutex->owner == whoami);

    if (--mutex->depth)
        return;

    mutex->owner = NULL;
    if (!jump_queue_empty((jump_queue_t*)&mutex->waiters))
        reactor_schedule(reactor, jump_queue_dequeue((jump_queue_t*)&mutex->waiters));
}

//
