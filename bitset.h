// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_BITSET_H
#define IOUCONTEXT_BITSET_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HIDDEN
#define HIDDEN __attribute__((visibility("hidden")))
#endif//HIDDEN

typedef struct bitset_s bitset_t;

HIDDEN bitset_t * bitset(size_t);
HIDDEN ssize_t bitset_get(bitset_t *);
HIDDEN size_t bitset_has(const bitset_t *);
HIDDEN bool bitset_lit(const bitset_t *, size_t);
HIDDEN size_t bitset_max(const bitset_t *);
HIDDEN void bitset_put(bitset_t *, size_t);
HIDDEN ssize_t bitset_two(bitset_t *);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_BITSET_H
