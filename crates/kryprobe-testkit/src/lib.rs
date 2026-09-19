// SPDX-License-Identifier: GPL-3.0-or-later
//! kryprobe-testkit: goldens, JSONL checks, and a manual clock.
//!
//! Deterministic test utilities shared by scripted backends and CLI tests:
//! [`ManualClock`] for reproducible time, [`assert_golden`] for byte-exact
//! golden files, and [`check_stream`] for structural JSONL validation driven
//! by a caller-supplied kind table (no backend knowledge here).
//!
//! K1 Task 2 adds [`alg_fixture`]: the committed AF_ALG traffic fixture
//! (exact-count crypto ops for the privileged kcrypto exactness suite).

pub mod alg_fixture;
pub mod clock;
pub mod golden;
pub mod jsonl;

pub use alg_fixture::{
    BurstCounts, CipherCounts, FixtureError, HashCounts, aead_decrypt_bad_tag, aead_roundtrip,
    burst_encrypt, hash_digest, hash_digest_multi, skcipher_roundtrip,
};
pub use clock::ManualClock;
pub use golden::{UPDATE_ENV_VAR, assert_golden};
pub use jsonl::{StreamChecker, StreamFinding, check_stream};
