// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_MACROS_H
#define IOUCONTEXT_MACROS_H

#include <errno.h>
#include <error.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define __VA_NUM_ARGS__(...) ({ \
    _Pragma("GCC diagnostic push") \
    _Pragma("GCC diagnostic ignored \"-Wint-conversion\"") \
    ((sizeof((const volatile void*[]){ NULL, ##__VA_ARGS__ })/sizeof(void*))-1); \
    _Pragma("GCC diagnostic pop") \
})

#define TRY(f, ...) ({ \
    typeof (f(__VA_ARGS__)) _result = f(__VA_ARGS__); \
    if (__builtin_expect(_result < 0, 0)) \
        error_at_line(EXIT_FAILURE, \
            ((uintptr_t)_result == -1) ? errno : -(uintptr_t)_result, \
            __FILE_NAME__, __LINE__, \
            "%s(%s)", #f, #__VA_ARGS__ \
        ); \
    _result; \
})

#define EXPECT(v, f, ...) ({ \
    typeof (f(__VA_ARGS__)) _result = f(__VA_ARGS__); \
    if (__builtin_expect(_result != v, 0)) \
        error_at_line(EXIT_FAILURE, \
            0, \
            __FILE_NAME__, __LINE__, \
            "%s(%s) expected %s", #f, #__VA_ARGS__, #v \
        ); \
    _result; \
})

#define ERRNO(f, ...) ({ \
    typeof (f (__VA_ARGS__)) _result = f(__VA_ARGS__); \
    _result < 0 ? ( errno = -_result), -1 : _result; \
})

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_MACROS_H
