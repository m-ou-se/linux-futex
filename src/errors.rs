#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WrongValueError {
	/// The futex value did not match the expected value.
	WrongValue,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitError {
	/// The futex value did not match the expected value.
	WrongValue,
	/// The operation was interrupted by a signal.
	Interrupted,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimedWaitError {
	/// The futex value did not match the expected value.
	WrongValue,
	/// The operation was interrupted by a signal.
	Interrupted,
	/// The timeout expired before the operation completed.
	TimedOut,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TryAgainError {
	/// The futex owner thread is about to exit, or the futex value did not match the expected value.
	TryAgain,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimedLockError {
	/// The futex owner thread is about to exit, but has not yet handled the internal state cleanup. Try again.
	TryAgain,
	/// The timeout expired before the operation completed.
	TimedOut,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimedRequeueError {
	/// The futex value did not match the expected value.
	WrongValue,
	/// The timeout expired before the operation completed.
	TimedOut,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequeuePiError {
	/// The futex value did not match the expected value, or the thread was woken up without being requeued to the [`PiFutex`][crate::PiFutex] first.
	TryAgain,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimedRequeuePiError {
	/// The futex value did not match the expected value, or the thread was woken up without being requeued to the [`PiFutex`][crate::PiFutex] first.
	TryAgain,
	/// The timeout expired before the operation completed.
	TimedOut,
}
