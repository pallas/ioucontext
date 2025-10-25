// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_FIBER_H
#define IOUCONTEXT_FIBER_H

#include "macros.h"

#include <ucontext.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ucontext_t ucontext_t;
typedef struct reactor_s reactor_t;

ucontext_t * fiber_get(reactor_t *);

#define reactor_fiber(function, reactor, ...) ({ \
    /* fprintf(stderr, "! %s(%s)\n", #function, #__VA_ARGS__); */ \
    typeof(function(reactor, ##__VA_ARGS__)) *_; \
    makecontext(fiber_get(reactor), (void(*)())function, __VA_NUM_ARGS__(void*, __VA_ARGS__) + 1, reactor, ##__VA_ARGS__); \
})

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_FIBER_H
