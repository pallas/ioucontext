// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_REACTOR_H
#define IOUCONTEXT_REACTOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct reactor_s reactor_t;

reactor_t * reactor_get();
void reactor_run(reactor_t *);
bool reactor_runnable(const reactor_t *);
bool reactor_running(const reactor_t *);
uintptr_t reactor_current(const reactor_t *);

void reactor__reactor_synchronize(reactor_t *);
static inline reactor_t * reactor_synchronize(reactor_t * reactor) {
    reactor__reactor_synchronize(reactor);
    return reactor;
}

typedef void (*reactor_cookie_eat_t)(void *cookie);
void * reactor_cookie(reactor_t *);
bool reactor_cookie_eat(reactor_t *);
void * reactor_cookie_jar(reactor_t *, void *cookie, reactor_cookie_eat_t);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_REACTOR_H
