// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned backend registry: duplicate `BackendId` is `Err`, never a panic.
//!
//! Ownership story (roadmap option (a)): the runtime owns every backend
//! handle in a `Vec<Box<dyn Backend>>`, and the registry hands out borrowed
//! `&dyn Backend` views tied to `&self`. Handles are `'static` (the
//! `Box<dyn Backend>` default), so backends own their configuration and
//! test doubles register as owned values; dropping the registry frees
//! every backend.
//! `Box<dyn Backend>` is `Send + Sync` because [`Backend`] requires both.

use crate::backend::Backend;
use crate::enums::BackendId;
use std::fmt::{Display, Formatter};

/// Registry of backends, keyed by [`BackendId`]; owns every handle.
#[derive(Default)]
pub struct BackendRegistry {
    backends: Vec<Box<dyn Backend>>,
}

impl std::fmt::Debug for BackendRegistry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let ids: Vec<BackendId> = self.backends.iter().map(|backend| backend.id()).collect();
        f.debug_struct("BackendRegistry")
            .field("backends", &ids)
            .finish()
    }
}

impl BackendRegistry {
    /// Empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an owned backend. A duplicate [`BackendId`] is a panic-free
    /// `Err` that leaves the registry unchanged; the rejected handle is
    /// dropped with the caller's `Err`, never leaked.
    pub fn register(&mut self, backend: Box<dyn Backend>) -> Result<(), DuplicateBackend> {
        let id = backend.id();
        if self.backends.iter().any(|known| known.id() == id) {
            return Err(DuplicateBackend { backend: id });
        }
        self.backends.push(backend);
        Ok(())
    }

    /// All registered backends, in registration order (borrowed views).
    #[must_use]
    pub fn discover_all(&self) -> Vec<&dyn Backend> {
        self.backends.iter().map(AsRef::as_ref).collect()
    }

    /// One backend by id, when registered.
    #[must_use]
    pub fn get(&self, id: BackendId) -> Option<&dyn Backend> {
        self.backends
            .iter()
            .find(|backend| backend.id() == id)
            .map(AsRef::as_ref)
    }
}

/// Rejected duplicate backend registration (caller error, not a defect).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateBackend {
    /// Already-registered id that was offered again.
    pub backend: BackendId,
}

impl Display for DuplicateBackend {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let name = match self.backend {
            BackendId::P11 => "p11",
            BackendId::OpenSsl => "openssl",
            BackendId::KCrypto => "kcrypto",
            BackendId::Synthetic => "synthetic",
        };
        write!(f, "duplicate backend: {name}")
    }
}

impl std::error::Error for DuplicateBackend {}
