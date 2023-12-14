// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_REACTOR_H
#define IOUCONTEXT_REACTOR_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct reactor_s reactor_t;

reactor_t * reactor_get();
void reactor_run(reactor_t *);
bool reactor_running(const reactor_t *);

typedef void (*reactor_cookie_eat_t)(void *cookie);
void * reactor_cookie(reactor_t *);
bool reactor_cookie_eat(reactor_t *);
void * reactor_cookie_jar(reactor_t *, void *cookie, reactor_cookie_eat_t);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_REACTOR_H
