// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_STACK_H
#define IOUCONTEXT_STACK_H

#include <signal.h>
#include <stdalign.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HIDDEN
#define HIDDEN __attribute__((visibility("hidden")))
#endif//HIDDEN

HIDDEN stack_t stack_get(size_t size);
HIDDEN stack_t stack_get_default();
HIDDEN stack_t stack_get_rlimit();
HIDDEN stack_t stack_get_signal();

HIDDEN stack_t stack_clear(stack_t);
HIDDEN stack_t stack_nofork(stack_t);
HIDDEN stack_t stack_dofork(stack_t);

HIDDEN void * stack_alloca(stack_t *, size_t, size_t);
#define stack_push(STACK, TYPE) ({ (TYPE*) stack_alloca((STACK), sizeof(TYPE), alignof(TYPE)); })
#define stack_array(STACK, TYPE, COUNT) ({ (TYPE*) stack_alloca((STACK), (COUNT) * sizeof(TYPE), alignof(TYPE)); })
HIDDEN void * stack_memcpy(stack_t *, const void *, size_t, size_t);
HIDDEN char * stack_strcpy(stack_t *, const char *);
HIDDEN stack_t stack_split(stack_t *, size_t, size_t);

HIDDEN void stack_put(stack_t);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_STACK_H
