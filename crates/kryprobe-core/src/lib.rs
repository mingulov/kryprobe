// SPDX-License-Identifier: GPL-3.0-or-later
//! kryprobe-core: stable identities, enums, errors, and probe plans.
//!
//! Follows CONTRACTS §1–§2, §4, §14. Wire spellings come from
//! `schemas/event-v0.schema.json`, which is authoritative over examples.

pub mod authority;
pub mod backend;
pub mod budget;
pub mod capability;
pub mod enums;
pub mod error;
pub mod evidence;
pub mod ids;
pub mod object;
pub mod plan;
pub mod program;

pub use program::ProgramId;
pub mod session;
pub mod synthetic;
pub mod target;
