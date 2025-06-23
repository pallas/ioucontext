// SPDX-License-Identifier: MIT
#include "stack.h"

#include "macros-internal.h"

#include <alloca.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>

stack_t
stack_get(size_t size) {
    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK | MAP_NORESERVE;
    stack_t s = {
        .ss_sp = TRY(mmap, NULL, size, prot, flags, -1, 0),
        .ss_size = size,
    };
    s.ss_flags = VALGRIND_STACK_REGISTER(s.ss_sp, s.ss_sp + s.ss_size);
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

static void * ptr_mask(void * p, uintptr_t m) { return (void*)( m & (uintptr_t)p); }

void *
stack_alloca(stack_t *s, size_t size, size_t align) {
    assert(align > 0);

    uintptr_t mask = align - 1;
    assert(0 == (align & mask));

    if (UNLIKELY(s->ss_size < size + align))
        return NULL;

    void * top = s->ss_sp + s->ss_size;
    void * bottom = s->ss_sp;

    void * data;
    if (stack_growsdown(0)) {
        data = ptr_mask(top - size, ~mask);
        assert(bottom <= data);
        s->ss_size = data - bottom;
    } else {
        data = ptr_mask(bottom + mask, ~mask);
        assert(data < top - size);
        s->ss_sp = data + size;
        s->ss_size = top - s->ss_sp;
    }

    assert(!mask || !ptr_mask(data, mask));
    return data;
}

void *
stack_memcpy(stack_t *s, const void *from, size_t size, size_t align) {
    void *to = stack_alloca(s, size, align);
    if (to)
        memcpy(to, from, size);
    return to;
}

char *
stack_strcpy(stack_t *s, const char *str) {
    return (char*)stack_memcpy(s, str, strlen(str) + 1, alignof(char));
}

stack_t
stack_split(stack_t *s, size_t size, size_t align) {
    assert(s->ss_size > size + align);
    return (stack_t) {
        .ss_sp = stack_alloca(s, size, align),
        .ss_size = size,
    };
}

void
stack_put(stack_t s) {
    VALGRIND_STACK_DEREGISTER(s.ss_flags);
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

stack_t stack_clear(stack_t stack) { madvise(stack.ss_sp, stack.ss_size, MADV_FREE); return stack; }
stack_t stack_nofork(stack_t stack) { madvise(stack.ss_sp, stack.ss_size, MADV_DONTFORK); return stack; }
stack_t stack_dofork(stack_t stack) { madvise(stack.ss_sp, stack.ss_size, MADV_DOFORK); return stack; }

//
