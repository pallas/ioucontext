// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_MACROS_INTERNAL_H
#define IOUCONTEXT_MACROS_INTERNAL_H

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

#endif//IOUCONTEXT_MACROS_INTERNAL_H
