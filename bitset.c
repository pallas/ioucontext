// SPDX-License-Identifier: MIT
#include "bitset.h"

#include "macros-internal.h"

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long long bitset_value_t;

enum {
    bitset_bits_per_value = sizeof(bitset_value_t) * CHAR_BIT,
    bitset_bias_per_value = bitset_bits_per_value - 1,
};

static const bitset_value_t bitset_value_one = 1;
static const bitset_value_t bitset_value_top = bitset_value_one << bitset_bias_per_value;
static const bitset_value_t bitset_value_all = ~0;

static inline bitset_value_t
bitset_value_bit(size_t bit) {
    assert(bit < bitset_bits_per_value);
    return bitset_value_one << bit;
}

static inline bitset_value_t
bitset_value_mask(size_t bit) {
    return bitset_value_bit(bit) - bitset_value_one;
}

typedef struct bitset_s {
    size_t bits;
    size_t hint;
    bitset_value_t values[];
} bitset_t;

bitset_t *
bitset(size_t bits) {
    const size_t n_values = (bits+bitset_bias_per_value)/bitset_bits_per_value;
    bitset_t *bitset = (bitset_t *)malloc(sizeof(bitset_t) + n_values * sizeof(bitset_value_t));
    if (bitset) {
        bitset->bits = bits;
        bitset->hint = 0;
        for (size_t i = 0 ; i < n_values - 1; ++i)
            bitset->values[i] = bitset_value_all;
        const size_t n_final = bits % bitset_bits_per_value;
        bitset->values[n_values - 1] = n_final ? bitset_value_mask(n_final) : bitset_value_all;
        assert(bitset->values[n_values - 1]);
    }

    return bitset;
}

ssize_t
bitset_get(bitset_t *bitset) {
    if (UNLIKELY(!bitset))
        return -1;
    const size_t n_values = (bitset->bits+bitset_bias_per_value)/bitset_bits_per_value;
    for (size_t i_value = bitset->hint ; i_value < n_values ; ++i_value) {
        bitset_value_t value = bitset->values[i_value];
        if (!value)
            continue;
        const size_t i_bit = __builtin_ctzll(value);
        assert(i_bit<bitset_bits_per_value);
        const bitset_value_t v_bit = bitset_value_bit(i_bit);
        assert(v_bit);
        assert(i_value * bitset_bits_per_value + i_bit < bitset->bits);
        bitset->values[i_value] &= ~v_bit;
        bitset->hint = i_value;
        return i_value * bitset_bits_per_value + i_bit;
    }
    return -1;
}

ssize_t
bitset_two(bitset_t *bitset) {
    if (UNLIKELY(!bitset))
        return -1;
    const size_t n_values = (bitset->bits+bitset_bias_per_value)/bitset_bits_per_value;
    for (size_t i_value = bitset->hint ; i_value < n_values ; ++i_value) {
        bitset_value_t value = bitset->values[i_value];
        if (!value)
            continue;

        for (size_t i_bit = 0 ; i_bit < bitset_bias_per_value ; ++i_bit) {
            const bitset_value_t mask = 0x3 << i_bit;
            if (mask == (bitset->values[i_value] & mask)) {
                bitset->values[i_value] &= ~mask;
                return i_value * bitset_bits_per_value + i_bit;
            }
        }

        if (( true
            && i_value+1 < n_values
            && (bitset->values[i_value+0] & bitset_value_top)
            && (bitset->values[i_value+1] & bitset_value_one)
            ))
        {
            bitset->values[i_value+0] &= ~bitset_value_top;
            bitset->values[i_value+1] &= ~bitset_value_one;
            return i_value * bitset_bits_per_value + bitset_bias_per_value;
        }
    }
    return -1;
}

size_t
bitset_has(const bitset_t *bitset) {
    size_t has = 0;
    const size_t n_values = (bitset->bits+bitset_bias_per_value)/bitset_bits_per_value;
    for (size_t i_value = bitset->hint ; i_value < n_values ; ++i_value)
        has += __builtin_popcountll(bitset->values[i_value]);
    return has;
}

bool
bitset_lit(const bitset_t *bitset, size_t bit) {
    if (UNLIKELY(bit >= bitset->bits))
        return false;
    const size_t n_values = (bitset->bits+bitset_bias_per_value)/bitset_bits_per_value;
    const size_t i_value = bit / bitset_bits_per_value;
    assert(i_value < n_values);
    const size_t i_bit = bit % bitset_bits_per_value;
    const bitset_value_t v_bit = bitset_value_bit(i_bit);
    return !(bitset->values[i_value] & v_bit);
}

size_t
bitset_max(const bitset_t *bitset) {
    return LIKELY(bitset) ? bitset->bits : 0;
}

void
bitset_put(bitset_t *bitset, size_t bit) {
    if (UNLIKELY(bit >= bitset->bits))
        abort();
    const size_t n_values = (bitset->bits+bitset_bias_per_value)/bitset_bits_per_value;
    const size_t i_value = bit / bitset_bits_per_value;
    assert(i_value < n_values);
    const size_t i_bit = bit % bitset_bits_per_value;
    const bitset_value_t v_bit = bitset_value_bit(i_bit);
    if (UNLIKELY(bitset->values[i_value] & v_bit))
        abort();
    if (bitset->hint > i_value)
        bitset->hint = i_value;
    bitset->values[i_value] |= v_bit;
}

//
