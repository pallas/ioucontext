// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_MACROS_INTERNAL_H
#define IOUCONTEXT_MACROS_INTERNAL_H

#include "macros.h"
#include <stdbool.h>

#ifdef HAVE_MEMCHECK_H
#include <valgrind/memcheck.h>
#include <string.h>
#define VALGRIND_CHECK_STRING(s) do { \
    const typeof (s) _s = s; \
    if (_s) \
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
#define VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(a,l) do { } while(false)
#define VALGRIND_MAKE_MEM_NOACCESS(a,l) do { } while(false)
#define VALGRIND_MAKE_MEM_UNDEFINED(a,l) do { } while(false)
#define VALGRIND_CHECK_STRING(s) do { } while(false)
#define VALGRIND_MAKE_BUFFER_DEFINED(a,l,r) do { } while(false)
#endif

#ifdef HAVE_HELGRIND_H
#include <valgrind/helgrind.h>
#else
#define VALGRIND_HG_DISABLE_CHECKING(a,l) do { } while (false)
#define VALGRIND_HG_MUTEX_INIT_POST(m,r) do { } while (false)
#define VALGRIND_HG_MUTEX_LOCK_PRE(m,t) do { } while (false)
#define VALGRIND_HG_MUTEX_LOCK_POST(m) do { } while (false)
#define VALGRIND_HG_MUTEX_UNLOCK_PRE(m) do { } while (false)
#define VALGRIND_HG_MUTEX_UNLOCK_POST(m) do { } while (false)
#define VALGRIND_HG_SEM_INIT_POST(s,v) do { } while (false)
#define VALGRIND_HG_SEM_WAIT_POST(s) do { } while (false)
#define VALGRIND_HG_SEM_POST_PRE(s) do { } while (false)
#endif

#ifndef RUNNING_ON_VALGRIND
#define RUNNING_ON_VALGRIND (false)
#endif

#define LIKELY(e) __builtin_expect(!!(e), true)
#define UNLIKELY(e) __builtin_expect(!!(e), false)

#define ADD_OVERFLOW_P(l, r) ({ \
    const typeof (l) _l = l; \
    const typeof (r) _r = r; \
    const static typeof (_l + _r) _z = 0; \
    __builtin_add_overflow_p(_l, _r, _z); \
})

#include <stddef.h>

#define TYPEOF_MEMBER(type, member) typeof(&((type *)NULL)->member)

#define CONTAINER_OF(pointer, type, member) ({ \
    typeof (pointer) _pointer = (pointer); \
    static const ptrdiff_t offset = offsetof(type, member); \
    _Generic(_pointer \
    , TYPEOF_MEMBER(const type, member) : (const type *)(((const char *)_pointer)-offset) \
    , TYPEOF_MEMBER(type, member) : (type *)(((char *)_pointer)-offset) \
    ); \
})

#endif//IOUCONTEXT_MACROS_INTERNAL_H
