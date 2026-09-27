// SPDX-License-Identifier: GPL-3.0-or-later
//! kcrypto lifecycle reducer: pure bounded edge semantics (TDD skeleton).

mod reducer;

pub use reducer::{
    CallbackDisposition, Edge, GapReason, LifecycleFamily, LifecycleReducer, OpDirection,
    ReducerStats, RequestMeta, RequestRecord, ReturnDisposition, Terminal,
};
