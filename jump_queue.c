// SPDX-License-Identifier: MIT
#include "jump_queue.h"

#include <assert.h>
#include <stddef.h>

void
jump_invoke(jump_chain_t * jc) {
    assert(jc->fun);
    jc->fun(jc->arg);
}

bool
jump_queue_empty(const jump_queue_t * jq) {
    return !jq->head;
}

void
jump_queue_reset(jump_queue_t * jq) {
    jq->head = NULL;
    jq->tail = &jq->head;
}

void
jump_queue_chain(jump_queue_t * hither, jump_queue_t * hence) {
    *hither->tail = hence->head;
    hither->tail = hence->tail;
    jump_queue_reset(hence);
}

void
jump_queue_enqueue(jump_queue_t * jq, jump_chain_t * jc) {
    assert(jc->fun);
    assert(!jc->next);

    *jq->tail = jc;
    jq->tail = &jc->next;

    assert(!jump_queue_empty(jq));
}

jump_chain_t *
jump_queue_dequeue(jump_queue_t * jq) {
    assert(!jump_queue_empty(jq));

    jump_chain_t * jc = jq->head;
    jq->head = jc->next;
    jc->next = NULL;

    if (jump_queue_empty(jq))
        jump_queue_reset(jq);

    assert(jc->fun);
    return jc;
}

void
jump_queue_requeue(jump_queue_t * jq, jump_chain_t * jc) {
    assert(jc->fun);
    assert(!jc->next);

    if (jump_queue_empty(jq)) {
        jump_queue_enqueue(jq, jc);
    } else {
        jc->next = jq->head;
        jq->head = jc;
    }

    assert(!jump_queue_empty(jq));
}


//
