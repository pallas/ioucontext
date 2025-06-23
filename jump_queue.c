// SPDX-License-Identifier: MIT
#include "jump_queue.h"

#include "reactor-internal.h"

#include <assert.h>
#include <stddef.h>

void
jump_invoke(jump_chain_t * jc, reactor_t * reactor) {
    assert(jc->function);
    reactor->current = jc->fiber;
    jc->function(jc);
}

jump_result_t
jump_result(const jump_chain_t * jc) {
    return jc->result;
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
    assert(jc->function);
    assert(!jc->next);

    if (jump_queue_empty(jq)) {
        jq->head = jc;
        jq->tail = &jc->next;
    } else {
        *jq->tail = jc;
        jq->tail = &jc->next;
    }

    assert(!jump_queue_empty(jq));
}

jump_chain_t *
jump_queue_dequeue(jump_queue_t * jq) {
    assert(!jump_queue_empty(jq));

    jump_chain_t * jc = jq->head;
    jq->head = jc->next;
    jc->next = NULL;

    assert(jc->function);
    return jc;
}

void
jump_queue_requeue(jump_queue_t * jq, jump_chain_t * jc) {
    assert(jc->function);
    assert(!jc->next);

    if (jump_queue_empty(jq)) {
        jq->head = jc;
        jq->tail = &jc->next;
    } else {
        jc->next = jq->head;
        jq->head = jc;
    }

    assert(!jump_queue_empty(jq));
}

//
