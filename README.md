# ioucontext

`ioucontext` is a coöperative multitasking framework built on top of
[liburing](https://github.com/axboe/liburing),
[libucontext](https://github.com/kaniini/libucontext),
[c-ares](https://github.com/c-ares/c-ares), &
[rustls](https://github.com/rustls/rustls-ffi).
It is the spiritual successor to
[liboco](https://github.com/pallas/liboco).

## Design
A thread-local `reactor` manages asynchronous `operations` submitted by one
or more `fiber`s, each with a built-in `stack`.  When invoked via
`reactor_run`, the reactor will run until all fibers terminate.  An explicit
choice has been made to use
[C11 threads](https://en.cppreference.com/w/c/thread)
over pthreads.

A new reactor will be initialized the first time `reactor_get` is called in
a particular thread; the underlying `io_uring` will attempt to pin itself to
one processor for which the thread has affinity.  The intention is to have
one io_uring running per thread, each pinned to one processor.

Fibers are created via `ucontext` but context-switching occurs via
`sigsetjmp`/`siglongjmp` to avoid the `sigprocmask` system call.  It is not
wise to modify the process signal mask after any fiber has been created,
whether or not it has run yet.

Operations that can not be immediately submitted to the underlying
`io_uring` will be deferred onto a wait-queue.  On completion, operations
return to the calling fiber directly.  Thus, fibers are written procedurally
but will coöperatively context-switch during operations.  Error codes are
typically returned as negative values.

Operations may be invoked outside of a fiber but may return prior to the
reactor completing all pending work.  In that case, `reactor_runnable` will
be true and an invocation of `reactor_run` will be required to clear the
work.

Reactors can store a user-data `cookie` and an optional destructor via
`reactor_cookie_jar`.  When the reactor is torn down, the cookie will be
eaten.

## Examples
 * iou_cat --- moves bytes between one or more input streams and stdout
 * iou_dns --- resolve dns forward and reverse lookups asynchronously
 * iou_port7 --- TCP & UDP echo service, à la [port7](https://github.com/pallas/port7)
 * iou_timers --- use multiple timerfds to make some noise
 * iou_tls --- STDIN -> TLS -> STDOUT

## Extra

This project is a toy, created out of a desire to better understand
[io_uring](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/io_uring)
and to atone for some of
[liboco](https://github.com/pallas/liboco)'s
sins.

Thanks to some wonderful resources, including
 * [Lord of the io_uring](https://unixism.net/loti/),
 * [Fibers, Oh My!](https://graphitemaster.github.io/fibers/),
 * [dankwiki](https://nick-black.com/dankwiki/index.php/Io_uring),
 * [archlinux](https://man.archlinux.org/listing/extra/liburing/), &
 * [LWN.net](https://lwn.net/).

License: [MIT](https://opensource.org/licenses/MIT)
