//! Futex: A Linux-specific fast user-space locking primitive.
//!
//! This crate provides easy-to-use wrappers around the not-so-easy-to-use `SYS_futex` Linux syscall.
//!
//! The documentation of Linux's futexes can be found in the
//! [relevant man page](http://man7.org/linux/man-pages/man2/futex.2.html).
//! The most important details are also explained in the documentation of this crate.
//!
//! The two main types of this crate are [`Futex`] and [`PiFutex`], which are
//! simply wrappers containing an [`AtomicI32`] exposing all the futex
//! operations Linux can apply to them.
//!
//! Existing [`AtomicI32`]s can be used as futexes through [`AsFutex`]
//! without changing their type.

mod errors;
mod scope;
mod sys;
mod timeout;

pub mod op;

use op::OpAndCmp;
use std::marker::PhantomData;
use std::sync::atomic::AtomicI32;
use std::time::{Duration, Instant};
use sys::{Error, FutexCall};
use timeout::as_timespec;

pub use errors::*;
pub use scope::{Private, Scope, Shared};
pub use timeout::Timeout;

/// A Linux-specific fast user-space locking primitive.
///
/// `Futex<Private>` may only be used from the same address space (the same
/// process) and is faster than a `Futex<Shared>`, which may be used accross
/// address spaces (processes).
#[repr(transparent)]
pub struct Futex<Scope> {
	pub value: AtomicI32,
	phantom: PhantomData<Scope>,
}

/// A Linux-specific priority inheriting fast user-space locking primitive.
///
/// Unlike with a regular [`Futex`], the value of a [`PiFutex`] has meaning
/// to the Linux kernel, taking away some flexibility. User-space must follow
/// the assumed protocol to allow the kernel to properly implement priority
/// inheritance.
///
/// See the *Priority-inheritance futexes* section of [the Linux futex man
/// page](http://man7.org/linux/man-pages/man2/futex.2.html) for details.
///
/// `PiFutex<Private>` may only be used from the same address space (the same
/// process) and is faster than a `PiFutex<Shared>`, which may be used accross
/// address spaces (processes).
#[repr(transparent)]
pub struct PiFutex<Scope> {
	pub value: AtomicI32,
	phantom: PhantomData<Scope>,
}

/// Use any [`AtomicI32`] as [`Futex`] or [`PiFutex`].
///
/// This also allows you to convert between a [`Futex`] and a [`PiFutex`] or
/// between [`Private`] and [`Shared`] futexes if you ever need that, as they
/// expose their internal [`AtomicI32`] through `.value`.
pub trait AsFutex<S> {
	fn as_futex(&self) -> &Futex<S>;
	fn as_pi_futex(&self) -> &PiFutex<S>;
}

impl<S> AsFutex<S> for AtomicI32 {
	#[must_use]
	#[inline]
	fn as_futex(&self) -> &Futex<S> {
		unsafe { std::mem::transmute(self) }
	}
	#[inline]
	#[must_use]
	fn as_pi_futex(&self) -> &PiFutex<S> {
		unsafe { std::mem::transmute(self) }
	}
}

impl<S> Futex<S> {
	/// Create a new [`Futex`] with an initial value.
	#[inline]
	pub const fn new(value: i32) -> Self {
		Self {
			value: AtomicI32::new(value),
			phantom: PhantomData,
		}
	}
}

impl<S> PiFutex<S> {
	/// Create a new [`PiFutex`] with an initial value.
	#[inline]
	pub const fn new(value: i32) -> Self {
		Self {
			value: AtomicI32::new(value),
			phantom: PhantomData,
		}
	}

	/// The `FUTEX_WAITERS` bit that indicates there are threads waiting.
	pub const WAITERS: i32 = -0x8000_0000;

	/// The `FUTEX_OWNER_DIED` bit that indicates the owning thread died.
	pub const OWNER_DIED: i32 = 0x4000_0000;

	/// The bits that are used for storing the thread id (`FUTEX_TID_MASK`).
	pub const TID_MASK: i32 = 0x3fffffff;
}

impl<S> Default for Futex<S> {
	fn default() -> Self {
		Self::new(0)
	}
}

impl<S> Default for PiFutex<S> {
	fn default() -> Self {
		Self::new(0)
	}
}

impl<S: Scope> Futex<S> {
	/// Wait until this futex is awoken by a `wake` call.
	///
	/// The thread will only be sent to sleep if the futex's value matches the
	/// expected value. Otherwise, it returns directly with [`WaitError::WrongValue`].
	#[inline]
	pub fn wait(&self, expected_value: i32) -> Result<(), WaitError> {
		let r = unsafe {
			FutexCall::new()
				.futex_op(libc::FUTEX_WAIT + S::futex_flag())
				.uaddr(&self.value)
				.val(expected_value)
				.call()
		};
		match r {
			Err(Error(libc::EAGAIN)) => Err(WaitError::WrongValue),
			Err(Error(libc::EINTR)) => Err(WaitError::Interrupted),
			Err(e) => e.panic("FUTEX_WAIT"),
			Ok(_) => Ok(()),
		}
	}

	/// Wait until this futex is awoken by a `wake` call, or until the timeout expires.
	///
	/// The thread will only be sent to sleep if the futex's value matches the
	/// expected value. Otherwise, it returns directly with [`TimedWaitError::WrongValue`].
	///
	/// If you want an absolute point in time as timeout, use
	/// [`wait_bitset_until`][Futex::wait_bitset_until] instead, using a bitset of `!0`.
	#[inline]
	pub fn wait_for(&self, expected_value: i32, timeout: Duration) -> Result<(), TimedWaitError> {
		let timeout = as_timespec(timeout);
		let r = unsafe {
			FutexCall::new()
				.futex_op(libc::FUTEX_WAIT + S::futex_flag())
				.uaddr(&self.value)
				.val(expected_value)
				.timeout(&timeout)
				.call()
		};
		match r {
			Err(Error(libc::EAGAIN)) => Err(TimedWaitError::WrongValue),
			Err(Error(libc::EINTR)) => Err(TimedWaitError::Interrupted),
			Err(Error(libc::ETIMEDOUT)) => Err(TimedWaitError::TimedOut),
			Err(e) => e.panic("FUTEX_WAIT"),
			Ok(_) => Ok(()),
		}
	}

	/// Wake up `n` waiters.
	///
	/// Returns the number of waiters that were woken up.
	#[inline]
	pub fn wake(&self, n: i32) -> i32 {
		let r = unsafe {
			FutexCall::new()
				.futex_op(libc::FUTEX_WAKE + S::futex_flag())
				.uaddr(&self.value)
				.val(n)
				.call()
		};
		match r {
			Err(e) => e.panic("FUTEX_WAKE"),
			Ok(v) => v,
		}
	}

	/// Wake up `n_wake` waiters, and requeue up to `n_requeue` waiters to another futex.
	///
	/// Returns the number of waiters that were woken up.
	#[inline]
	pub fn requeue(&self, n_wake: i32, to: &Futex<S>, n_requeue: i32) -> i32 {
		let r = unsafe {
			FutexCall::new()
				.futex_op(libc::FUTEX_REQUEUE + S::futex_flag())
				.uaddr(&self.value)
				.uaddr2(&to.value)
				.val(n_wake)
				.val2(n_requeue)
				.call()
		};
		match r {
			Err(e) => e.panic("FUTEX_REQUEUE"),
			Ok(v) => v,
		}
	}

	/// Wake up `n_wake` waiters, and requeue up to `n_requeue` waiters to another futex.
	///
	/// The operation will only execute if the futex's value matches the
	/// expected value. Otherwise, it returns directly with a [`WrongValueError`].
	///
	/// Returns the total number of waiters that were woken up or requeued to the other futex.
	#[inline]
	pub fn cmp_requeue(
		&self,
		expected_value: i32,
		n_wake: i32,
		to: &Futex<S>,
		n_requeue: i32,
	) -> Result<i32, WrongValueError> {
		let r = unsafe {
			FutexCall::new()
				.futex_op(libc::FUTEX_CMP_REQUEUE + S::futex_flag())
				.uaddr(&self.value)
				.uaddr2(&to.value)
				.val(n_wake)
				.val2(n_requeue)
				.val3(expected_value)
				.call()
		};
		match r {
			Err(Error(libc::EAGAIN)) => Err(WrongValueError::WrongValue),
			Err(e) => e.panic("FUTEX_CMP_REQUEUE"),
			Ok(v) => Ok(v),
		}
	}

	/// Wait until this futex is awoken by a `wake` call matching a bitset.
	///
	/// - Calls to [`wake`][Futex::wake] will match any bitset.
	/// - Calls to [`wake_bitset`][Futex::wake_bitset] will match if at least one 1-bit matches.
	///
	/// The thread will only be sent to sleep if the futex's value matches the
	/// expected value. Otherwise, it returns directly with [`WaitError::WrongValue`].
	#[inline]
	pub fn wait_bitset(&self, expected_value: i32, bitset: u32) -> Result<(), WaitError> {
		let r = unsafe {
			FutexCall::new()
				.uaddr(&self.value)
				.futex_op(libc::FUTEX_WAIT_BITSET + S::futex_flag())
				.val(expected_value)
				.val3(bitset as i32)
				.call()
		};
		match r {
			Err(Error(libc::EAGAIN)) => Err(WaitError::WrongValue),
			Err(Error(libc::EINTR)) => Err(WaitError::Interrupted),
			Err(e) => e.panic("FUTEX_WAIT_BITSET"),
			Ok(_) => Ok(()),
		}
	}

	/// Wait until this futex is awoken by a `wake` call matching a bitset, or until the timeout expires.
	///
	/// - Calls to [`wake`][Futex::wake] will match any bitset.
	/// - Calls to [`wake_bitset`][Futex::wake_bitset] will match if at least one 1-bit matches.
	///
	/// The thread will only be sent to sleep if the futex's value matches the
	/// expected value. Otherwise, it returns directly with [`TimedWaitError::WrongValue`].
	#[inline]
	pub fn wait_bitset_until(
		&self,
		expected_value: i32,
		bitset: u32,
		timeout: impl Timeout,
	) -> Result<(), TimedWaitError> {
		let timeout = timeout.as_timespec();
		let r = unsafe {
			FutexCall::new()
				.uaddr(&self.value)
				.futex_op(libc::FUTEX_WAIT_BITSET + timeout.0 + S::futex_flag())
				.val(expected_value)
				.val3(bitset as i32)
				.timeout(&timeout.1)
				.call()
		};
		match r {
			Err(Error(libc::EAGAIN)) => Err(TimedWaitError::WrongValue),
			Err(Error(libc::EINTR)) => Err(TimedWaitError::Interrupted),
			Err(Error(libc::ETIMEDOUT)) => Err(TimedWaitError::TimedOut),
			Err(e) => e.panic("FUTEX_WAIT_BITSET"),
			Ok(_) => Ok(()),
		}
	}

	/// Wake up `n` waiters matching a bitset.
	///
	/// - Waiters waiting using [`wait`][Futex::wait] are always woken up,
	///   regardless of the bitset.
	/// - Waiters waiting using [`wait_bitset`][Futex::wait_bitset] are woken up
	///   if they match at least one 1-bit.
	///
	/// Returns the number of waiters that were woken up.
	#[inline]
	pub fn wake_bitset(&self, n: i32, bitset: u32) -> i32 {
		let r = unsafe {
			FutexCall::new()
				.futex_op(libc::FUTEX_WAKE_BITSET + S::futex_flag())
				.uaddr(&self.value)
				.val(n)
				.val3(bitset as i32)
				.call()
		};
		match r {
			Err(e) => e.panic("FUTEX_WAKE_BITSET"),
			Ok(v) => v,
		}
	}

	/// Wake up `n` waiters, and conditionally `n2` waiters on another futex after modifying it.
	///
	/// This operation first applies an [operation][`op::Op`] to the second futex while remembering its old value,
	/// then wakes up `n` waiters on the first futex, and finally wakes `n2` waiters on the second futex if
	/// its old value matches [a condition][`op::Cmp`]. This all happens atomically.
	///
	/// Returns the total number of waiters that were woken up on either futex.
	#[inline]
	pub fn wake_op(&self, n: i32, second: &Futex<S>, op: OpAndCmp, n2: i32) -> i32 {
		let r = unsafe {
			FutexCall::new()
				.futex_op(libc::FUTEX_WAKE_OP + S::futex_flag())
				.uaddr(&self.value)
				.uaddr2(&second.value)
				.val(n)
				.val2(n2)
				.val3(op.raw_bits() as i32)
				.call()
		};
		match r {
			Err(e) => e.panic("FUTEX_WAKE_OP"),
			Ok(v) => v,
		}
	}

	/// Wake up one waiter, and requeue up to `n_requeue` to a [`PiFutex`].
	///
	/// Only requeues waiters that are blocked by [`wait_requeue_pi`][Futex::wait_requeue_pi]
	/// or [`wait_requeue_pi_until`][Futex::wait_requeue_pi_until].
	/// The [`PiFutex`] must be the same as the one the waiters are waiting to be requeued to.
	///
	/// The number of waiters to wake cannot be chosen and is always 1.
	///
	/// Returns the total number of waiters that were woken up or requeued to the other futex.
	#[inline]
	pub fn cmp_requeue_pi(
		&self,
		expected_value: i32,
		to: &PiFutex<S>,
		n_requeue: i32,
	) -> Result<i32, TryAgainError> {
		let r = unsafe {
			FutexCall::new()
				.futex_op(libc::FUTEX_CMP_REQUEUE_PI + S::futex_flag())
				.uaddr(&self.value)
				.uaddr2(&to.value)
				.val(1)
				.val2(n_requeue)
				.val3(expected_value)
				.call()
		};
		match r {
			Err(Error(libc::EAGAIN)) => Err(TryAgainError::TryAgain),
			Err(e) => e.panic("FUTEX_CMP_REQUEUE_PI"),
			Ok(v) => Ok(v),
		}
	}

	/// Wait until this futex is awoken after potentially being requeued to a [`PiFutex`].
	///
	/// A call to [`cmp_requeue_pi`][Futex::cmp_requeue_pi] will requeue this waiter to
	/// the [`PiFutex`]. The call must refer to the same [`PiFutex`].
	///
	/// A call to [`wake`][Futex::wake] (or [`wake_bitset`][Futex::wake_bitset]) will
	/// wake this thread without requeueing. This results in an [`RequeuePiError::TryAgain`].
	#[inline]
	pub fn wait_requeue_pi(
		&self,
		expected_value: i32,
		second: &PiFutex<S>,
	) -> Result<(), RequeuePiError> {
		let r = unsafe {
			FutexCall::new()
				.futex_op(libc::FUTEX_WAIT_REQUEUE_PI + S::futex_flag())
				.uaddr(&self.value)
				.uaddr2(&second.value)
				.val(expected_value)
				.call()
		};
		match r {
			Err(Error(libc::EAGAIN)) => Err(RequeuePiError::TryAgain),
			Err(e) => e.panic("FUTEX_WAIT_REQUEUE_PI"),
			Ok(_) => Ok(()),
		}
	}

	/// Wait until this futex is awoken after potentially being requeued to a [`PiFutex`], or until the timeout expires.
	///
	/// A call to [`cmp_requeue_pi`][Futex::cmp_requeue_pi] will requeue this waiter to
	/// the [`PiFutex`]. The call must refer to the same [`PiFutex`].
	///
	/// A call to [`wake`][Futex::wake] (or [`wake_bitset`][Futex::wake_bitset]) will
	/// wake this thread without requeueing. This results in an [`TimedRequeuePiError::TryAgain`].
	#[inline]
	pub fn wait_requeue_pi_until(
		&self,
		expected_value: i32,
		second: &PiFutex<S>,
		timeout: impl Timeout,
	) -> Result<(), TimedRequeuePiError> {
		let timeout = timeout.as_timespec();
		let r = unsafe {
			FutexCall::new()
				.futex_op(libc::FUTEX_WAIT_REQUEUE_PI + timeout.0 + S::futex_flag())
				.uaddr(&self.value)
				.uaddr2(&second.value)
				.val(expected_value)
				.timeout(&timeout.1)
				.call()
		};
		match r {
			Err(Error(libc::EAGAIN)) => Err(TimedRequeuePiError::TryAgain),
			Err(Error(libc::ETIMEDOUT)) => Err(TimedRequeuePiError::TimedOut),
			Err(e) => e.panic("FUTEX_WAIT_REQUEUE_PI"),
			Ok(_) => Ok(()),
		}
	}
}

impl<S: Scope> PiFutex<S> {
	/// See `FUTEX_LOCK_PI` in the [Linux futex man page](http://man7.org/linux/man-pages/man2/futex.2.html).
	#[inline]
	pub fn lock_pi(&self) -> Result<(), TryAgainError> {
		let r = unsafe {
			FutexCall::new()
				.futex_op(libc::FUTEX_LOCK_PI + S::futex_flag())
				.uaddr(&self.value)
				.call()
		};
		match r {
			Err(Error(libc::EAGAIN)) => Err(TryAgainError::TryAgain),
			Err(e) => e.panic("FUTEX_LOCK_PI"),
			Ok(_) => Ok(()),
		}
	}

	/// See `FUTEX_LOCK_PI` in the [Linux futex man page](http://man7.org/linux/man-pages/man2/futex.2.html).
	#[inline]
	pub fn lock_pi_until(&self, timeout: impl Timeout) -> Result<(), TimedLockError> {
		const FUTEX_LOCK_PI2: i32 = 13;
		let (clock, timespec) = timeout.as_timespec();
		let op = if clock == libc::FUTEX_CLOCK_REALTIME {
			libc::FUTEX_LOCK_PI
		} else {
			// Only available since Linux 5.14.
			FUTEX_LOCK_PI2
		};
		let r = unsafe {
			FutexCall::new()
				.futex_op(op + S::futex_flag())
				.uaddr(&self.value)
				.timeout(&timespec)
				.call()
		};
		match r {
			Err(Error(libc::EAGAIN)) => Err(TimedLockError::TryAgain),
			Err(Error(libc::ETIMEDOUT)) => Err(TimedLockError::TimedOut),
			Err(e) if op == FUTEX_LOCK_PI2 => e.panic("FUTEX_LOCK_PI2"),
			Err(e) => e.panic("FUTEX_LOCK_PI"),
			Ok(_) => Ok(()),
		}
	}

	/// See `FUTEX_TRYLOCK_PI` in the [Linux futex man page](http://man7.org/linux/man-pages/man2/futex.2.html).
	#[inline]
	pub fn trylock_pi(&self) -> Result<(), TryAgainError> {
		let r = unsafe {
			FutexCall::new()
				.futex_op(libc::FUTEX_TRYLOCK_PI + S::futex_flag())
				.uaddr(&self.value)
				.call()
		};
		match r {
			Err(Error(libc::EAGAIN)) => Err(TryAgainError::TryAgain),
			Err(e) => e.panic("FUTEX_LOCK_PI"),
			Ok(_) => Ok(()),
		}
	}

	/// See `FUTEX_UNLOCK_PI` in the [Linux futex man page](http://man7.org/linux/man-pages/man2/futex.2.html).
	#[inline]
	pub fn unlock_pi(&self) {
		let r = unsafe {
			FutexCall::new()
				.futex_op(libc::FUTEX_UNLOCK_PI + S::futex_flag())
				.uaddr(&self.value)
				.call()
		};
		if let Err(e) = r {
			e.panic("FUTEX_UNLOCK_PI");
		}
	}
}

impl<S> std::fmt::Debug for Futex<S> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		f.debug_struct("Futex")
			.field("scope", &std::any::type_name::<S>())
			.field("value", &self.value)
			.finish()
	}
}

impl<S> std::fmt::Debug for PiFutex<S> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		f.debug_struct("PiFutex")
			.field("scope", &std::any::type_name::<S>())
			.field("value", &self.value)
			.finish()
	}
}
