// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_TIMESPEC_H
#define IOUCONTEXT_TIMESPEC_H

#include <limits.h>
#include <stdbool.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

static const struct timespec timespec_block = { .tv_sec = -1, };
static const struct timespec timespec_zero = { .tv_sec = 0, .tv_nsec = 0, };

struct timespec reify_timespec(const struct timespec);
struct timespec normalize_timespec(const struct timespec);
struct timespec timespec_s(long);
struct timespec timespec_ms(long);
struct timespec timespec_ns(long);
struct timespec timespec_from_double(double);
double double_from_timespec(const struct timespec);

int timespec_when(const struct timespec);
bool timespec_past(const struct timespec);
bool timespec_present(const struct timespec);
bool timespec_future(const struct timespec);
bool timespec_normalized(const struct timespec);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_TIMESPEC_H
