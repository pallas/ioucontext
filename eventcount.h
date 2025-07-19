// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_EVENTCOUNT_H
#define IOUCONTEXT_EVENTCOUNT_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct reactor_s reactor_t;

typedef uint32_t iou_eventcount_ticket_t;
typedef struct iou_eventcount_s {
    _Atomic iou_eventcount_ticket_t ticket;
} iou_eventcount_t;

void iou_eventcount(iou_eventcount_t *);
iou_eventcount_ticket_t iou_eventcount_ticket(reactor_t *, const iou_eventcount_t *);
iou_eventcount_ticket_t iou_eventcount_wait(reactor_t *, iou_eventcount_t *, const iou_eventcount_ticket_t);
void iou_eventcount_wake(reactor_t *, iou_eventcount_t *, int n);
void iou_eventcount_wake_all(reactor_t *, iou_eventcount_t *);

typedef struct iou_eventcount__state_s {
    reactor_t * reactor;
    iou_eventcount_t * eventcount;
    iou_eventcount_ticket_t ticket;
} iou_eventcount__state_t;

#define iou_eventcount_until(REACTOR, EVENTCOUNT, ...) for \
( iou_eventcount__state_t state = ({ \
    const typeof (REACTOR) _reactor = (REACTOR); \
    const typeof (EVENTCOUNT) _eventcount = (EVENTCOUNT); \
    (iou_eventcount__state_t) { \
        .reactor = _reactor, \
        .eventcount = _eventcount, \
        .ticket = iou_eventcount_ticket(_reactor, _eventcount), \
    }; }) \
; !(__VA_ARGS__) \
; state.ticket = iou_eventcount_wait(state.reactor, state.eventcount, state.ticket) \
)

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_EVENTCOUNT_H
