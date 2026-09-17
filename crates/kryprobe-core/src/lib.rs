// SPDX-License-Identifier: GPL-3.0-or-later
//! kryprobe-core: stable identities, enums, errors, and probe plans.
//!
//! Follows CONTRACTS §1–§2, §4, §14. Wire spellings come from
//! `schemas/event-v0.schema.json`, which is authoritative over examples.

pub mod enums;
pub mod error;
pub mod ids;
pub mod object;
pub mod plan;
pub mod target;
