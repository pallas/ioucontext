// SPDX-License-Identifier: MIT
#ifndef IOUCONTEXT_OUTPUT_H
#define IOUCONTEXT_OUTPUT_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct reactor_s reactor_t;


typedef struct iou_output_s {
    enum iou_output_types {
        iou_output_none,
        iou_output_send,
        iou_output_splice,
        iou_output_write,
        n_iou_output_types,
    } type;
    union {
        struct {
            size_t length;
            const void *buffer;
        } info_send;
        struct {
            size_t length;
            int fd_in;
            off_t *off_in;
            int drain:1;
        } info_splice;
        struct {
            size_t length;
            const void *buffer;
        } info_write;
    };
} iou_output_t;

ssize_t iou__n_output(reactor_t * reactor, int fd_out, const off_t *off_out, size_t n_outs, iou_output_t * const outs[]);
#define iou_output(REACTOR, FD_OUT, OFF_OUT, ...) ({ \
    const off_t *_off_out = OFF_OUT; \
    const size_t _n_outputs = __VA_NUM_ARGS__(iou_output_t, __VA_ARGS__); \
    iou_output_t _outputs[] = { __VA_ARGS__ }; \
    assert(_n_outputs == (sizeof(_outputs)/sizeof(*_outputs))); \
    iou_output_t * _output_pointers[_n_outputs]; \
    for (size_t i = 0 ; i < _n_outputs ; ++i) \
        _output_pointers[i] = &_outputs[i]; \
    ssize_t _result = iou__n_output(REACTOR, FD_OUT, _off_out, _n_outputs, _output_pointers); \
    if (_result > 0 && _off_out && _off_out >= 0) _off_out += _result; \
    _result; \
})

#define iou_output_none() ((iou_output_t){ .type = iou_output_none, })
#define iou_output_send(...) ((iou_output_t){ .type = iou_output_send, .info_send = { __VA_ARGS__ } })
#define iou_output_splice(...) ((iou_output_t){ .type = iou_output_splice, .info_splice = { __VA_ARGS__ } })
#define iou_output_write(...) ((iou_output_t){ .type = iou_output_write, .info_write = { __VA_ARGS__ } })

ssize_t iou_spaceout(reactor_t *, int fd);

#ifdef __cplusplus
}
#endif

#endif//IOUCONTEXT_OUTPUT_H
