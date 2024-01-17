// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <ioucontext/ioucontext.h>

#include <sched.h>
#include <stdlib.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

void
buzz(reactor_t * reactor, int i, char *arg) {
    struct timespec delta = timespec_from_double(strtod(arg, NULL));
    struct itimerspec its = {
        .it_interval = delta,
        .it_value = delta,
    };

    int tfd = TRY(timerfd_create, CLOCK_BOOTTIME, TFD_CLOEXEC);
    TRY(timerfd_settime, tfd, 0, &its, NULL);

    uint64_t count;
    while (sizeof count == iou_read(reactor, tfd, &count, sizeof count)) {
        struct timespec now;
        TRY(clock_gettime, CLOCK_BOOTTIME, &now);
        int n = iou_printf(reactor, STDOUT_FILENO, "%*s%16f\n", i*16, "", double_from_timespec(now));
        if (n < 0)
            exit(n);
    }
}

int
main(int argc, char *argv[]) {
    cpu_set_t cpu_set;
    CPU_ZERO_S(sizeof(cpu_set_t), &cpu_set);
    CPU_SET_S(0, sizeof(cpu_set_t), &cpu_set);
    TRY(sched_setaffinity, 0, sizeof(cpu_set_t), &cpu_set);

    reactor_t * reactor = reactor_get();

    for (int i = 1 ; i < argc ; ++i)
        if (strtod(argv[i], NULL) > 0.0)
            reactor_fiber(buzz, reactor, i-1, argv[i]);

    reactor_run(reactor);

    return 0;
}

//
