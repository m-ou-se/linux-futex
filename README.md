# linux-futex

Futex: A Linux-specific fast user-space locking primitive.

This crate provides easy-to-use wrappers around the not-so-easy-to-use `SYS_futex` Linux syscall.

The documentation of Linux's futexes can be found in the
[relevant man page](http://man7.org/linux/man-pages/man2/futex.2.html).
The most important details are also explained in the documentation of this crate.

The two main types of this crate are [`Futex`](https://docs.rs/linux-futex/*/linux_futex/struct.Futex.html)
and [`PiFutex`](https://docs.rs/linux-futex/*/linux_futex/struct.PiFutex.html), which are
simply wrappers containing an `AtomicU32` exposing all the futex operations Linux can apply to them.

Existing `AtomicU32`s can be used as futexes through
[`AsFutex`](https://docs.rs/linux-futex/*/linux_futex/trait.AsFutex.html)
without changing their type.
