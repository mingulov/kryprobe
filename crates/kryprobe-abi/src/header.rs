// SPDX-License-Identifier: GPL-3.0-or-later
//! Wire event envelope: `RawEventHeader`, `SpineEvent`, `split_header`.
//!
//! Layout follows CONTRACTS §3. All structs are `#[repr(C)]` with frozen
//! size/alignment asserts in `tests/abi_layout.rs`.

use core::fmt;
use core::mem::{align_of, size_of};

use crate::ids::ABI_VERSION;

/// Raw BPF event envelope: header followed by a backend-owned payload.
///
/// 56 bytes, alignment 8. Integers are native little-endian on the
/// supported x86-64 target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct RawEventHeader {
    pub abi_version: u16,
    pub backend_id: u16,
    pub event_kind: u16,
    pub flags: u16,
    pub total_len: u32,
    pub cpu: u32,
    pub session_cookie: u64,
    pub monotonic_ns: u64,
    pub tgid: u32,
    pub tid: u32,
    pub process_generation: u64,
    pub plan_generation: u32,
    pub reserved: u32,
}

/// Fixed 64-byte BPF→userspace spine record (T7 `bpf-spine` shares this).
///
/// 64 bytes, alignment 8. `reserved` pads the record to its frozen size
/// and must be zeroed by producers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SpineEvent {
    pub cookie: u64,
    pub tgid: u32,
    pub tid: u32,
    pub monotonic_ns: u64,
    pub seq: u64,
    pub flags: u32,
    pub reserved: [u8; 28],
}

/// Decode failure for [`split_header`]; every variant carries the offending values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AbiError {
    /// Fewer than `expected` header bytes present (`actual` seen).
    Truncated { expected: usize, actual: usize },
    /// Buffer address `addr` is not `align`-byte aligned.
    Misaligned { addr: usize, align: usize },
    /// `total_len` disagrees with the buffer: claims more bytes than present,
    /// or fewer than the header itself occupies.
    LengthMismatch { total_len: u32, buffer_len: usize },
    /// `abi_version` is not [`ABI_VERSION`].
    UnknownVersion { version: u16 },
    /// The buffer holds more bytes than `total_len` accounts for.
    TrailingBytes { total_len: u32, buffer_len: usize },
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            AbiError::Truncated { expected, actual } => write!(
                f,
                "truncated event buffer: need {expected} header bytes, got {actual}"
            ),
            AbiError::Misaligned { addr, align } => write!(
                f,
                "event buffer at address {addr:#x} is not {align}-byte aligned"
            ),
            AbiError::LengthMismatch {
                total_len,
                buffer_len,
            } => write!(
                f,
                "event total_len {total_len} disagrees with buffer length {buffer_len}"
            ),
            AbiError::UnknownVersion { version } => {
                write!(f, "unknown event abi_version {version}")
            }
            AbiError::TrailingBytes {
                total_len,
                buffer_len,
            } => write!(
                f,
                "event buffer length {buffer_len} exceeds total_len {total_len}"
            ),
        }
    }
}

impl core::error::Error for AbiError {}

/// Splits `bytes` into its [`RawEventHeader`] borrow and backend payload.
///
/// Checks, in order: the buffer holds a full header, the address is
/// 8-byte aligned, the version is [`ABI_VERSION`], `total_len` covers
/// exactly the buffer (neither short, impossible, nor trailing).
///
/// Every failure — including misalignment — is a returned [`AbiError`],
/// never a panic.
pub fn split_header(bytes: &[u8]) -> Result<(&RawEventHeader, &[u8]), AbiError> {
    let header_len = size_of::<RawEventHeader>();
    if bytes.len() < header_len {
        return Err(AbiError::Truncated {
            expected: header_len,
            actual: bytes.len(),
        });
    }
    let addr = bytes.as_ptr() as usize;
    let align = align_of::<RawEventHeader>();
    if !addr.is_multiple_of(align) {
        return Err(AbiError::Misaligned { addr, align });
    }
    // SAFETY: length and alignment both checked above, so the header
    // range is a valid aligned `RawEventHeader` borrow for `bytes`' lifetime.
    let header = unsafe { &*(bytes.as_ptr().cast::<RawEventHeader>()) };
    if header.abi_version != ABI_VERSION {
        return Err(AbiError::UnknownVersion {
            version: header.abi_version,
        });
    }
    let total = header.total_len as usize;
    if total < header_len || total > bytes.len() {
        return Err(AbiError::LengthMismatch {
            total_len: header.total_len,
            buffer_len: bytes.len(),
        });
    }
    if total < bytes.len() {
        return Err(AbiError::TrailingBytes {
            total_len: header.total_len,
            buffer_len: bytes.len(),
        });
    }
    Ok((header, &bytes[header_len..total]))
}
