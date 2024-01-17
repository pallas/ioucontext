// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include "arena.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static size_t
__attribute__((const))
to_page_size(size_t size) {
    const size_t page_size = sysconf(_SC_PAGESIZE);
    const size_t page_mask = page_size - 1;
    assert(0 == (page_size & page_mask));
    return size + (-size & page_mask);
}

struct chunk_s {
    chunk_t *prev;
    void * data;
    size_t size;
};

static inline size_t
chunk_len(chunk_t * chunk) {
    return chunk->size;
}

static inline void *
chunk_end(chunk_t * chunk) {
    return ((void*)chunk) + chunk_len(chunk);
};

static inline bool
chunk_has(chunk_t * chunk, void * data) {
    void * first = chunk + 1;
    return first <= data && data < chunk_end(chunk);
}

static inline size_t
chunk_left(chunk_t * chunk) {
    return chunk_end(chunk) - chunk->data;
}

static void *
chunk_add(chunk_t * chunk, size_t size) {
    if (chunk_left(chunk) < size) {
        size_t have = chunk->size;
        size_t want = to_page_size(chunk->size - chunk_left(chunk) + size);
        if (MAP_FAILED == mremap(chunk, have, want, 0))
            return NULL;
        chunk->size = want;
    }
    assert(chunk_left(chunk) >= size);
    chunk->data += size;
    return chunk->data - size;
}

static inline bool
chunk_pad(chunk_t * chunk, size_t align) {
    const size_t mask = align - 1;
    assert(0 == (align & mask));
    size_t pad = -(uintptr_t)chunk->data & mask;
    return chunk_add(chunk, pad);
}

static chunk_t *
chunk_put(chunk_t *chunk) {
    assert(chunk);
    chunk_t * prev = chunk->prev;
    munmap(chunk, chunk->size);
    return prev;
}

static chunk_t *
__attribute__ ((malloc, malloc(chunk_put, 1)))
chunk_get(size_t size) {
    size = to_page_size(size + sizeof(chunk_t));

    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
    chunk_t * chunk = (chunk_t *) mmap(NULL, size, prot, flags, -1, 0);
    if (MAP_FAILED == chunk)
        return NULL;

    *chunk = (chunk_t) {
        .size = size,
        .data = chunk + 1,
    };
    assert(chunk_has(chunk, chunk->data));

    return chunk;
}

static void *
arena_oom(arena_t * arena) {
    if (arena->oom_fun)
        return arena->oom_fun(arena->oom_arg);

    return NULL;
}

static bool
arena_grow(arena_t * arena, size_t size) {
    chunk_t * future = chunk_get(size);
    if (!future)
        return !!arena_oom(arena);

    if (arena->object) {
        assert(chunk_has(arena->current, arena->object) || arena->object == chunk_end(arena->current));
        if (arena->align > 1)
            chunk_pad(future, arena->align);
        size_t bytes = arena->current->data - arena->object;
        assert(bytes == arena->size);
        if (bytes) {
            arena->object = memcpy(chunk_add(future, bytes), arena->object, bytes);
            arena->current->data -= bytes;
        } else {
            arena->object = future->data;
        }
    }

    future->prev = arena->current;
    arena->current = future;

    return true;
}

bool
arena__plant(arena_t * arena, size_t align) {
    assert(!arena->object);
    if (!arena->current && !arena_grow(arena, 1))
        return false;

    if (!chunk_pad(arena->current, align) && !arena_grow(arena, align))
        return false;

    arena->object = arena->current->data;
    arena->align = align;
    arena->size = 0;

    return true;
}

void *
arena__water(arena_t * arena, size_t size) {
    assert(arena->object);
    assert(chunk_has(arena->current, arena->object) || arena->object == chunk_end(arena->current));
    void * data = chunk_add(arena->current, size);
    if (!data) {
        if (!arena_grow(arena, size + arena->size + arena->align))
            return NULL;
        data = chunk_add(arena->current, size);
        if (!data)
            return arena_oom(arena);
    }

    arena->size += size;
    assert(arena->size == arena->current->data - arena->object);
    assert(chunk_has(arena->current, arena->object) || arena->object == chunk_end(arena->current));
    return data;
}

void *
__attribute__ ((malloc))
arena_bloom(arena_t * arena) {
    assert(arena->object);
    void * data = arena->object;
    arena->object = NULL;
    arena->align = 1;
    arena->size = 0;
    return data;
}

void
arena_reset(arena_t * arena) {
    if (arena->object) {
        arena->current->data = arena->object;
        arena->object = NULL;
        arena->align = 1;
        arena->size = 0;
    }
}

void *
__attribute__ ((malloc, alloc_size(2), alloc_align(3)))
arena__new(arena_t * arena, size_t size, size_t align)
{
    if (arena__plant(arena, align) && arena__water(arena, size))
        return arena_bloom(arena);
    arena_reset(arena);
    return NULL;
}

void
arena_cull(arena_t * arena, void * data) {
    assert(!arena->object);
    while (arena->current) {
        if (chunk_has(arena->current, data)) {
            arena->current->data = data;
            return;
        }
        arena->current = chunk_put(arena->current);
    }
    assert(!data);
}

void *
arena_memcpy(arena_t * arena, const void *from, size_t size, size_t align) {
    void *to = arena__new(arena, size, align);
    return to ? memcpy(to, from, size) : NULL;
}

char *
arena_strcpy(arena_t * arena, const char * str) {
    return (char*)arena_memcpy(arena, str, strlen(str) + 1, alignof(char));
}

//
