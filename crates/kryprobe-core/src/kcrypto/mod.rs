// SPDX-License-Identifier: GPL-3.0-or-later
//! kcrypto lifecycle reducer: pure bounded edge semantics (TDD skeleton).

pub mod aead;
mod reducer;

pub use reducer::{
    AeadMeta, CallbackDisposition, Edge, GapReason, LifecycleFamily, LifecycleReducer, OpDirection,
    ReducerStats, RequestMeta, RequestRecord, ReturnDisposition, Terminal,
};
