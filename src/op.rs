//! Arguments to the [`wake_op`][crate::Futex::wake_op] function.

/// The operation [`wake_op`][crate::Futex::wake_op] applies to the second futex.
///
/// An [`Op`] must be combined with a [`Cmp`] by using the plus operator. For
/// example: `Op::assign(1) + Cmp::eq(0)`
///
/// The argument to any operation must be below `1 << 12` (= 4096).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Op {
	bits: u32,
}

impl Op {
	/// Assign the argument to the futex value: `value = arg`
	#[inline]
	pub fn assign(arg: u32) -> Self {
		Self::new(0, arg)
	}

	/// Add the argument to the futex value: `value += arg`
	#[inline]
	pub fn add(arg: u32) -> Self {
		Self::new(1, arg)
	}

	/// Bitwise-or the futex value with the argument: `value |= arg`
	#[inline]
	pub fn or(arg: u32) -> Self {
		Self::new(2, arg)
	}

	/// Bitwise-and the futex value with the bitwise complement of the argument: `value &= !arg`
	#[inline]
	pub fn and_not(arg: u32) -> Self {
		Self::new(3, arg)
	}

	/// Xor the futex value with the argument: `value ^= arg`
	#[inline]
	pub fn xor(arg: u32) -> Self {
		Self::new(4, arg)
	}

	/// Assign `1 << bit` to the futex value: `value = 1 << bit`
	#[inline]
	pub fn assign_bit(bit: u32) -> Self {
		Self::new(8, bit)
	}

	/// Add `1 << bit` to the futex value: `value += 1 << bit`
	#[inline]
	pub fn add_bit(bit: u32) -> Self {
		Self::new(9, bit)
	}

	/// Set the `bit`th bit of the futex value: `value |= 1 << bit`
	#[inline]
	pub fn set_bit(bit: u32) -> Self {
		Self::new(10, bit)
	}

	/// Clear the `bit`th bit of the futex value: `value &= !(1 << bit)`
	#[inline]
	pub fn clear_bit(bit: u32) -> Self {
		Self::new(11, bit)
	}

	/// Toggle the `bit`th bit of the futex value: `value ^= 1 << bit`
	#[inline]
	pub fn toggle_bit(bit: u32) -> Self {
		Self::new(12, bit)
	}

	#[inline]
	fn new(op: u32, value: u32) -> Self {
		if value >= 1 << 12 {
			panic!("Value too large: {}", value);
		}
		Self {
			bits: value << 12 | op << 28,
		}
	}
}

impl std::fmt::Debug for Op {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		let op = match self.bits >> 28 {
			0 => "assign",
			1 => "add",
			2 => "or",
			3 => "and_not",
			4 => "xor",
			8 => "assign_bit",
			9 => "add_bit",
			10 => "set_bit",
			11 => "clear_bit",
			12 => "toggle_bit",
			_ => "invalid",
		};
		write!(f, "Op::{}({})", op, self.bits >> 12 & 0xFFF)
	}
}

/// The comparison [`wake_op`][crate::Futex::wake_op] applies to the old value of the second futex.
///
/// A [`Cmp`] must be combined with an [`Op`] by using the plus operator. For
/// example: `Op::assign(1) + Cmp::eq(0)`
///
/// The argument to any comparison must be below `1 << 12` (= 4096).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Cmp {
	bits: u32,
}

impl Cmp {
	/// Check if the old value of the futex equals this value.
	#[inline]
	pub fn eq(value: u32) -> Self {
		Self::new(0, value)
	}

	/// Check if the old value of the futex does not equal this value.
	#[inline]
	pub fn ne(value: u32) -> Self {
		Self::new(1, value)
	}

	/// Check if the old value of the futex is less than this value.
	#[inline]
	pub fn lt(value: u32) -> Self {
		Self::new(2, value)
	}

	/// Check if the old value of the futex is less than or equal to this value.
	#[inline]
	pub fn le(value: u32) -> Self {
		Self::new(3, value)
	}

	/// Check if the old value of the futex is greater than this value.
	#[inline]
	pub fn gt(value: u32) -> Self {
		Self::new(4, value)
	}

	/// Check if the old value of the futex is greater than or equal to this value.
	#[inline]
	pub fn ge(value: u32) -> Self {
		Self::new(5, value)
	}

	#[inline]
	fn new(op: u32, value: u32) -> Self {
		if value >= 1 << 12 {
			panic!("Value too large: {}", value);
		}
		Self {
			bits: value | op << 24,
		}
	}
}

impl std::fmt::Debug for Cmp {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		let op = match self.bits >> 24 & 0xF {
			0 => "eq",
			1 => "ne",
			2 => "lt",
			3 => "le",
			4 => "gt",
			5 => "ge",
			_ => "invalid",
		};
		write!(f, "Cmp::{}({})", op, self.bits & 0xFFF)
	}
}

/// The operation and comparison [`wake_op`][crate::Futex::wake_op] applies to the second futex.
///
/// See [`Op`] and [`Cmp`].
///
/// To obtain a [`OpAndCmp`], an [`Op`] and [`Cmp`] must be combined by using
/// the plus operator. For example: `Op::assign(1) + Cmp::eq(0)`
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OpAndCmp {
	bits: u32,
}

impl OpAndCmp {
	#[inline]
	pub const fn from_raw_bits(bits: u32) -> Self {
		Self { bits }
	}

	#[inline]
	pub const fn raw_bits(self) -> u32 {
		self.bits
	}
}

impl std::ops::Add<Cmp> for Op {
	type Output = OpAndCmp;
	#[inline]
	fn add(self, cmp: Cmp) -> OpAndCmp {
		OpAndCmp {
			bits: self.bits | cmp.bits,
		}
	}
}

impl std::fmt::Debug for OpAndCmp {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(
			f,
			"{:?} + {:?}",
			Op { bits: self.bits },
			Cmp { bits: self.bits }
		)
	}
}
