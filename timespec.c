// SPDX-License-Identifier: MIT
#include "timespec.h"

#include "macros-internal.h"

#include <assert.h>
#include <time.h>

enum {
    msec_per_sec = 1000,
    nsec_per_msec = 1000000,
    nsec_per_sec = 1000000000,
};

static inline struct timespec
__normalize_timespec(const struct timespec ts) {
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

static bool
__timespec_normalized(struct timespec ts) {
    struct timespec normal = __normalize_timespec(ts);
    return ts.tv_sec == normal.tv_sec
        && ts.tv_nsec == normal.tv_nsec
        && ts.tv_nsec >= 0
        ;
}

struct timespec
reify_timespec(const struct timespec delta) {
    struct timespec now;
    TRY(clock_gettime, CLOCK_BOOTTIME, &now);

    return __normalize_timespec((struct timespec){
        now.tv_sec + delta.tv_sec,
        now.tv_nsec + delta.tv_nsec,
    });
}

struct timespec
dereify_timespec(const struct timespec when) {
    struct timespec now;
    TRY(clock_gettime, CLOCK_BOOTTIME, &now);

    return __normalize_timespec((struct timespec){
        when.tv_sec - now.tv_sec,
        when.tv_nsec - now.tv_nsec,
    });
}

struct timespec
normalize_timespec(const struct timespec ts) {
    return __normalize_timespec(ts);
}

struct timespec timespec_s(long s) { return __normalize_timespec((const struct timespec){ .tv_sec = s }); }
struct timespec timespec_ms(long ms) { return __normalize_timespec((const struct timespec){ .tv_sec = ms / msec_per_sec, .tv_nsec = (ms % msec_per_sec) * nsec_per_msec }); }
struct timespec timespec_ns(long ns) { return __normalize_timespec((const struct timespec){ .tv_nsec = ns }); }

struct timespec
timespec_from_double(double d) {
    return __normalize_timespec((struct timespec){
        .tv_sec = (time_t)d,
        .tv_nsec = nsec_per_sec * (d - (time_t)d),
    });
}

double
double_from_timespec(const struct timespec ts) {
    assert(__timespec_normalized(ts));
    return ts.tv_sec + ts.tv_nsec / (double)nsec_per_sec;
}

int
timespec_when(const struct timespec ts) {
    assert(__timespec_normalized(ts));
    return timespec_past(ts) ? -1
        :  timespec_present(ts) ? 0
        :  timespec_future(ts) ? 1
        :  (abort(),0);
}

bool
timespec_past(const struct timespec ts) {
    assert(__timespec_normalized(ts));
    return ts.tv_sec < 0;
}

bool
timespec_present(const struct timespec ts) {
    assert(__timespec_normalized(ts));
    return ts.tv_sec == 0 && ts.tv_nsec == 0;
}

bool
timespec_future(const struct timespec ts) {
    assert(__timespec_normalized(ts));
    return ts.tv_sec > 0 || (ts.tv_sec == 0 && ts.tv_nsec > 0);
}

//
