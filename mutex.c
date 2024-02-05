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
    assert(reactor->current);
    assert(!mutex->owner || mutex->depth);

    if (!mutex->owner)
        mutex->owner = reactor->current;

    return mutex->owner == reactor->current && ++mutex->depth;
}

void
iou_mutex_enter(reactor_t * reactor, iou_mutex_t * mutex) {
    assert(reactor->current);
    assert(!mutex->owner || mutex->depth);
    while (!iou_mutex_probe(reactor, mutex)) {
        todo_sigjmp_t todo;
        if (!sigsetjmp(*make_todo_sigjmp(&todo, reactor->current), false)) {
            jump_queue_enqueue((jump_queue_t*)&mutex->waiters, &todo.jump);
            reactor_enter_core(reactor);
        }
    }
    assert(mutex->owner == reactor->current);
}

bool
iou_mutex_owner(reactor_t * reactor, const iou_mutex_t * mutex) {
    assert(!mutex->owner || mutex->depth);
    return mutex->owner == reactor->current;
}

void
iou_mutex_leave(reactor_t * reactor, iou_mutex_t * mutex) {
    assert(mutex->depth);
    assert(mutex->owner == reactor->current);

    if (--mutex->depth)
        return;

    mutex->owner = NULL;
    if (!jump_queue_empty((jump_queue_t*)&mutex->waiters))
        reactor_schedule(reactor, jump_queue_dequeue((jump_queue_t*)&mutex->waiters));
}

//
