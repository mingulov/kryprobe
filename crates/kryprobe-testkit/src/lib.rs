// SPDX-License-Identifier: GPL-3.0-or-later
#![warn(missing_docs)]
//! kryprobe-testkit: dev-only fixtures and golden helpers.
//!
//! 1B-M4: production code must never depend on this crate — the manual
//! clock lives in core (`kryprobe_core::synthetic::ManualClock`) and the
//! stream checker in report (`kryprobe_report::checker`); what remains here
//! is fixtures
//! ([`alg_fixture`]: committed AF_ALG traffic for the privileged
//! exactness suite) and [`assert_golden`] for byte-exact golden files.
//! All dependents wire this crate through `[dev-dependencies]`.

pub mod alg_fixture;
pub mod golden;
pub mod kcrypto_rows;

pub use alg_fixture::{
    BurstCounts, CipherCounts, FixtureError, HashCounts, aead_decrypt_bad_tag, aead_roundtrip,
    burst_encrypt, hash_digest, hash_digest_multi, skcipher_canary_roundtrip, skcipher_roundtrip,
};
pub use golden::{UPDATE_ENV_VAR, assert_golden};
