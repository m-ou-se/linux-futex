use std::ptr::null;
use std::sync::atomic::AtomicI32;

#[must_use]
pub struct FutexCall {
	uaddr: *const AtomicI32,
	futex_op: i32,
	val: i32,
	timeout: *const libc::timespec,
	uaddr2: *const AtomicI32,
	val3: i32,
}

impl FutexCall {
	#[inline]
	pub const fn new() -> Self {
		Self {
			uaddr: null(),
			futex_op: 0,
			val: 0,
			timeout: null(),
			uaddr2: null(),
			val3: 0,
		}
	}

	#[inline]
	pub fn uaddr(self, uaddr: *const AtomicI32) -> Self {
		Self { uaddr, ..self }
	}

	#[inline]
	pub fn futex_op(self, futex_op: i32) -> Self {
		Self { futex_op, ..self }
	}

	#[inline]
	pub fn val(self, val: i32) -> Self {
		Self { val, ..self }
	}

	#[inline]
	pub fn timeout(self, timeout: *const libc::timespec) -> Self {
		Self { timeout, ..self }
	}

	#[inline]
	pub fn val2(self, val2: i32) -> Self {
		Self {
			timeout: val2 as *const _,
			..self
		}
	}

	#[inline]
	pub fn uaddr2(self, uaddr2: *const AtomicI32) -> Self {
		Self { uaddr2, ..self }
	}

	#[inline]
	pub fn val3(self, val3: i32) -> Self {
		Self { val3, ..self }
	}

	#[inline]
	pub unsafe fn call(self) -> Result<i32, Error> {
		let result = libc::syscall(
			libc::SYS_futex,
			self.uaddr,
			self.futex_op,
			self.val,
			self.timeout,
			self.uaddr2,
			self.val3,
		) as i32;
		if result == -1 {
			Err(Error(*libc::__errno_location()))
		} else {
			Ok(result)
		}
	}
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Error(pub i32);

impl Error {
	pub fn panic(self, name: &str) -> ! {
		panic!("{}: {}", name, std::io::Error::from_raw_os_error(self.0));
	}
}
