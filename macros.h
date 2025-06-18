// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_MACROS_H
#define IOUCONTEXT_MACROS_H

#include <errno.h>
#include <error.h>
#include <stdbool.h>
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

#define LIKELY(e) __builtin_expect(!!(e), true)
#define UNLIKELY(e) __builtin_expect(!!(e), false)

#ifdef __cplusplus
}
#endif

#ifdef HAVE_MEMCHECK_H
#include <valgrind/memcheck.h>
#include <string.h>
#define VALGRIND_CHECK_STRING(s) do { \
    if (const typeof (s) _s = s) \
        VALGRIND_CHECK_MEM_IS_DEFINED(_s, strlen(_s)); \
} while (false)
#define VALGRIND_MAKE_BUFFER_DEFINED(a,l,r) do { \
    const typeof (l) _l = l; \
    const typeof (r) _r = r; \
    if (_l > 0) \
        VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(a, _l < _r ? _l : _r); \
} while (false)
#else
#define VALGRIND_STACK_DEREGISTER(s) do { } while(false)
#define VALGRIND_STACK_REGISTER(a,l) (0)
#define VALGRIND_CHECK_MEM_IS_ADDRESSABLE(a,l) do { } while(false)
#define VALGRIND_CHECK_MEM_IS_DEFINED(a,l) do { } while(false)
#define VALGRIND_CHECK_VALUE_IS_DEFINED(v) do { } while(false)
#define VALGRIND_MAKE_MEM_DEFINED(a,l) do { } while(false)
#define VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE do { } while(false)
#define VALGRIND_MAKE_MEM_UNDEFINED(a,l) do { } while(false)
#define VALGRIND_CHECK_STRING(s) do { } while(false)
#define VALGRIND_MAKE_BUFFER_DEFINED(a,l,r) do { } while(false)
#define RUNNING_ON_VALGRIND (false)
#endif

#endif//IOUCONTEXT_MACROS_H
