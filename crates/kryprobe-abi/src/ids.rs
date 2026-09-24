// SPDX-License-Identifier: GPL-3.0-or-later
//! Wire IDs: ABI version, backend IDs, session cookies, event kinds.
//!
//! Values follow CONTRACTS §1–§3. No Rust enum crosses the BPF boundary;
//! the wire carries plain integers and these consts name them.

/// Wire ABI version carried in every [`crate::RawEventHeader`].
pub const ABI_VERSION: u16 = 0;

/// PKCS#11 backend (CONTRACTS §2 `BackendId::P11`).
/// Retired/reserved: no p11 backend ships (ADR-0004); the value stays
/// frozen so old records keep their meaning. Never reassign.
pub const BACKEND_P11: u16 = 1;
/// OpenSSL backend (CONTRACTS §2 `BackendId::OpenSsl`).
/// Reserved for possible future use (ADR-0004); no backend ships today.
/// Never reassign.
pub const BACKEND_OPENSSL: u16 = 2;
/// kcrypto backend (CONTRACTS §2 `BackendId::KCrypto`).
pub const BACKEND_KCRYPTO: u16 = 3;
/// Reserved synthetic backend ID (test-only).
///
/// CONTRACTS §2 names only p11/openssl/kcrypto; selftest events need a wire
/// value that can never collide with a real backend. Real backends never
/// emit this value and any non-test decoder must reject events carrying it.
pub const BACKEND_SYNTHETIC: u16 = 0xFF;

/// Observation event: a backend saw a cryptographic operation.
pub const EVENT_OBSERVATION: u16 = 1;
/// Loss event: the backend reports dropped or missed observations.
pub const EVENT_LOSS: u16 = 2;
/// Barrier event: ordering/completeness marker in the event stream.
pub const EVENT_BARRIER: u16 = 3;

/// Opaque session-scoped cookie binding an event to its observation session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SessionCookie(pub u64);

/// Wire event kind discriminator (see `EVENT_*` consts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct EventKind(pub u16);
