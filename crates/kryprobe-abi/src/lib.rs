// SPDX-License-Identifier: GPL-3.0-or-later
//! kryprobe-abi: shared BPF/userspace wire IDs and event header.
//!
//! Follows CONTRACTS §1–§3. This crate is `no_std` (core-only) so BPF
//! programs share it verbatim; only the tests link std.

#![cfg_attr(not(test), no_std)]

pub mod header;
pub mod ids;

pub use header::{AbiError, RawEventHeader, SpineEvent, split_header};
pub use ids::{
    ABI_VERSION, BACKEND_KCRYPTO, BACKEND_OPENSSL, BACKEND_P11, BACKEND_SYNTHETIC, EVENT_BARRIER,
    EVENT_LOSS, EVENT_OBSERVATION, EventKind, SessionCookie,
};
