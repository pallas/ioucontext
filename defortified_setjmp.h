// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_DEFORTIFIED_SETJMP_H
#define IOUCONTEXT_DEFORTIFIED_SETJMP_H

#ifdef _FORTIFY_SOURCE
#ifdef _SETJMP_H
#error "<setjmp.h> with FORTIFY_SOURCE breaks stack switching"
#endif
#pragma push_macro("_FORTIFY_SOURCE")
#undef _FORTIFY_SOURCE
#include <setjmp.h>
#pragma pop_macro("_FORTIFY_SOURCE")
#else
#include <setjmp.h>
#endif

#endif//IOUCONTEXT_DEFORTIFIED_SETJMP_H
