// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_STACK_H
#define IOUCONTEXT_STACK_H

#include <signal.h>
#include <stdalign.h>

#ifdef __cplusplus
extern "C" {
#endif

stack_t stack_get(size_t size);
stack_t stack_get_rlimit();
stack_t stack_get_signal();

stack_t stack_clear(stack_t);
stack_t stack_nofork(stack_t);
stack_t stack_dofork(stack_t);

void * stack_alloca(stack_t *, size_t, size_t);
#define stack_push(STACK, TYPE) ({ (TYPE*) stack_alloca((STACK), sizeof(TYPE), alignof(TYPE)); })
stack_t stack_split(stack_t *, size_t, size_t);

void stack_put(stack_t);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_STACK_H
