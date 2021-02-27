use libc::{c_long, time_t};
use std::time::{Duration, Instant, SystemTime};

/// A point in time on either the monotonic clock ([`Instant`]) or real time clock ([`SystemTime`]).
pub unsafe trait Timeout {
	#[doc(hidden)]
	fn as_timespec(self) -> (i32, libc::timespec);
}

unsafe impl Timeout for Instant {
	#[inline]
	#[doc(hidden)]
	fn as_timespec(self) -> (i32, libc::timespec) {
		(
			0,
			as_timespec(self.duration_since(unsafe { std::mem::zeroed() })),
		)
	}
}

unsafe impl Timeout for SystemTime {
	#[inline]
	#[doc(hidden)]
	fn as_timespec(self) -> (i32, libc::timespec) {
		(
			libc::FUTEX_CLOCK_REALTIME,
			as_timespec(self.duration_since(SystemTime::UNIX_EPOCH).unwrap()),
		)
	}
}

#[inline]
pub(crate) fn as_timespec(d: Duration) -> libc::timespec {
	libc::timespec {
		tv_sec: d.as_secs() as time_t,
		tv_nsec: d.subsec_nanos() as c_long,
	}
}
