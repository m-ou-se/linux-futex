/// A type indicating a futex is only used from the same address space (process).
#[derive(Clone, Copy, Debug)]
pub struct Private(());

/// A type indicating a futex might be used from multiple address spaces (processes).
#[derive(Clone, Copy, Debug)]
pub struct Shared(());

/// [`Private`] or [`Shared`].
pub unsafe trait Scope {
	fn futex_flag() -> i32;
}

unsafe impl Scope for Private {
	#[inline]
	fn futex_flag() -> i32 {
		libc::FUTEX_PRIVATE_FLAG
	}
}

unsafe impl Scope for Shared {
	#[inline]
	fn futex_flag() -> i32 {
		0
	}
}
