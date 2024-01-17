// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_ARENA_H
#define IOUCONTEXT_ARENA_H

#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct arena_s arena_t;
typedef struct chunk_s chunk_t;

typedef void * arena_oom_arg_t;
typedef void * (*arena_oom_fun_t)(arena_oom_arg_t);

struct arena_s {
    chunk_t *current;
    void * object;
    size_t align, size;
    arena_oom_fun_t oom_fun;
    arena_oom_arg_t oom_arg;
};

void *
__attribute__ ((malloc, alloc_size(2), alloc_align(3)))
arena__new(arena_t * arena, size_t size, size_t align);

#define arena_new(ARENA, TYPE) ((TYPE*)arena__new(ARENA, sizeof(TYPE), alignof(TYPE)))
#define arena_copy(ARENA, OBJECT) ({ \
    void * __data = arena__new(ARENA, sizeof(*OBJECT), alignof(*OBJECT)); \
    (typeof(OBJECT)) __data ? memcpy(__data, (OBJECT), sizeof(*(OBJECT))) : NULL; \
})
void * arena_memcpy(arena_t * arena, const void *, size_t size, size_t align);
char * arena_strcpy(arena_t * arena, const char *);

bool arena__plant(arena_t * arena, size_t align);
#define arena_plant(ARENA, TYPE) (arena__plant(ARENA, alignof(TYPE)))
void * arena__water(arena_t * arena, size_t size);
#define arena_water(ARENA, TYPE) ((TYPE*)arena__water(ARENA, sizeof(TYPE)))
void * __attribute__ ((malloc)) arena_bloom(arena_t * arena);
void arena_reset(arena_t * arena);

void arena_cull(arena_t * arena, void *);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_ARENA_H
