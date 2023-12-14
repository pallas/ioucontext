// SPDX-License-Identifier: MIT
#include "timespec.h"

#include "macros.h"

#include <assert.h>
#include <time.h>

static const long nsec_per_sec = 1000000000;

struct timespec
reify_timespec(const struct timespec delta) {
    struct timespec now;
    TRY(clock_gettime, CLOCK_BOOTTIME, &now);

    return normalize_timespec((struct timespec){
        now.tv_sec + delta.tv_sec,
        now.tv_nsec + delta.tv_nsec,
    });
}

struct timespec
normalize_timespec(const struct timespec ts) {
    struct timespec normal = ts;

    if (normal.tv_nsec <= -nsec_per_sec || normal.tv_nsec >= nsec_per_sec) {
        normal.tv_sec += normal.tv_nsec / nsec_per_sec;
        normal.tv_nsec %= nsec_per_sec;
    }

    if (normal.tv_nsec < 0) {
        normal.tv_sec -= 1;
        normal.tv_nsec += nsec_per_sec;
    }

    return normal;
}

struct timespec
timespec_from_double(double d) {
    return normalize_timespec((struct timespec){
        .tv_sec = (time_t)d,
        .tv_nsec = nsec_per_sec * (d - (time_t)d),
    });
}

double
double_from_timespec(const struct timespec ts) {
    assert(timespec_normalized(ts));
    return ts.tv_sec + ts.tv_nsec / (double)nsec_per_sec;
}

bool
timespec_future(const struct timespec ts) {
    assert(timespec_normalized(ts));
    return ts.tv_sec > 0 || (ts.tv_sec == 0 && ts.tv_nsec > 0);
}

bool
timespec_normalized(struct timespec ts) {
    struct timespec normal = normalize_timespec(ts);
    return ts.tv_sec == normal.tv_sec && ts.tv_nsec == normal.tv_nsec && ts.tv_nsec >= 0;
}

//
