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
#include <unistd.h>

static size_t stack__page_size = 0;
static size_t __stack__page_size() { return sysconf(_SC_PAGESIZE); }
__attribute__((constructor)) static void stack__page_size_construct(void) {
    stack__page_size = __stack__page_size();
}

static __attribute__((const)) size_t
stack_page_size() {
    if (UNLIKELY(!stack__page_size))
        stack__page_size = __stack__page_size();

    return stack__page_size;
}

stack_t
stack_get(size_t size) {
    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK | MAP_NORESERVE;

    const size_t page_size = stack_page_size();
    const size_t page_mask = page_size - 1;
    assert(0 == (page_size & page_mask));
    const size_t round_size = size + (-size & page_mask);

    void * first = mmap(NULL, round_size + 2*page_size, prot, flags, -1, 0);
    if (UNLIKELY(MAP_FAILED == first))
        abort();
    stack_t s = {
        .ss_sp = first + page_size,
        .ss_size = round_size,
    };
    s.ss_flags = VALGRIND_STACK_REGISTER(s.ss_sp, s.ss_sp + s.ss_size);

    TRY(mprotect, first, page_size, PROT_NONE);
    VALGRIND_MAKE_MEM_NOACCESS(first, page_size);

    void * last = first + page_size + round_size;
    TRY(mprotect, last, page_size, PROT_NONE);
    VALGRIND_MAKE_MEM_NOACCESS(last, page_size);

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
    const size_t page_size = stack_page_size();
    TRY(munmap, s.ss_sp - page_size, s.ss_size + 2*page_size);
}

static rlim_t
rlimit_stack() {
    struct rlimit rl;
    TRY(getrlimit, RLIMIT_STACK, &rl);
    return rl.rlim_cur;
}

static size_t
__stack__default_size() {
    size_t min_stack_size = SIGSTKSZ;
    size_t max_stack_size = rlimit_stack();

    const char * env_stack_size = getenv("IOUCONTEXT_STACK_SIZE");
    size_t stack_size = env_stack_size ? strtol(env_stack_size, NULL, 0) : 131072;

    return stack_size < min_stack_size ? min_stack_size
        : stack_size > max_stack_size ? max_stack_size
        : stack_size;
}

static size_t stack__default_size = 0;
__attribute__((constructor)) static void stack__default_size_construct(void) { stack__default_size = __stack__default_size(); }

stack_t
stack_get_default() {
    if (!stack__default_size)
        stack__default_size = __stack__default_size();

    return stack_get(stack__default_size);
}

stack_t stack_get_rlimit() { return stack_get(rlimit_stack()); }
stack_t stack_get_signal() { return stack_get(SIGSTKSZ); }

stack_t stack_clear(stack_t stack) { madvise(stack.ss_sp, stack.ss_size, MADV_FREE); return stack; }
stack_t stack_nofork(stack_t stack) { madvise(stack.ss_sp, stack.ss_size, MADV_DONTFORK); return stack; }
stack_t stack_dofork(stack_t stack) { madvise(stack.ss_sp, stack.ss_size, MADV_DOFORK); return stack; }

//
