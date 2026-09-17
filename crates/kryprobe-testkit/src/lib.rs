// SPDX-License-Identifier: GPL-3.0-or-later
//! kryprobe-testkit: goldens, JSONL checks, and a manual clock.
//!
//! Deterministic test utilities shared by scripted backends and CLI tests:
//! [`ManualClock`] for reproducible time, [`assert_golden`] for byte-exact
//! golden files, and [`check_stream`] for structural JSONL validation driven
//! by a caller-supplied kind table (no backend knowledge here).

pub mod clock;
pub mod golden;
pub mod jsonl;

pub use clock::ManualClock;
pub use golden::{UPDATE_ENV_VAR, assert_golden};
pub use jsonl::{StreamFinding, check_stream};
