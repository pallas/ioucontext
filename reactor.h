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
typedef struct jump_chain_s jump_chain_t;

reactor_t * reactor_get();
void reactor_run(reactor_t *);
bool reactor_runnable(const reactor_t *);
bool reactor_running(const reactor_t *);
uintptr_t reactor_current(const reactor_t *);

void reactor_max_workers(reactor_t *, unsigned bounded, unsigned unbounded);

void reactor_park(reactor_t *, jump_chain_t **);
void reactor_schedule(reactor_t *, jump_chain_t *);

typedef void (*reactor_cookie_eat_t)(void *cookie);
void * reactor_cookie(reactor_t *);
bool reactor_cookie_eat(reactor_t *);
void * reactor_cookie_jar(reactor_t *, void *cookie, reactor_cookie_eat_t);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_REACTOR_H
