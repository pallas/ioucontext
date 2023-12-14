// SPDX-License-Identifier: MIT
#include "stack.h"

#include "macros.h"

#include <alloca.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>

#ifdef HAVE_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

stack_t
stack_get(size_t size) {
    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK | MAP_NORESERVE;
    stack_t s = {
        .ss_sp = TRY(mmap, NULL, size, prot, flags, -1, 0),
        .ss_size = size,
    };
#ifdef HAVE_MEMCHECK_H
    s.ss_flags = VALGRIND_STACK_REGISTER(s.ss_sp, s.ss_sp + s.ss_size);
#endif
    return s;
}

static
__attribute__((__noinline__))
uintptr_t stack_pointer(volatile uintptr_t p, ...) {
    return (uintptr_t)&p;
}

static
__attribute__((__noinline__))
bool stack_growsdown(volatile uintptr_t p, ...) {
    assert((uintptr_t)&p != stack_pointer(p));
    return (uintptr_t)&p > stack_pointer(p);
}

void *
stack_alloca(stack_t *s, size_t size) {
    if (UNLIKELY(s->ss_size < size))
        return NULL;

    if (stack_growsdown(0)) {
        s->ss_size -= size;
        return s->ss_sp + s->ss_size;
    } else {
        s->ss_size -= size;
        s->ss_sp += size;
        return s->ss_sp - size;
    }
}

void
stack_put(stack_t s) {
#ifdef HAVE_MEMCHECK_H
    VALGRIND_STACK_DEREGISTER(s.ss_flags);
#endif
    TRY(munmap, s.ss_sp, s.ss_size);
}

rlim_t
rlimit_stack() {
    struct rlimit rl;
    TRY(getrlimit, RLIMIT_STACK, &rl);
    return rl.rlim_cur;
}

stack_t stack_get_rlimit() { return stack_get(rlimit_stack()); }
stack_t stack_get_signal() { return stack_get(SIGSTKSZ); }

//
