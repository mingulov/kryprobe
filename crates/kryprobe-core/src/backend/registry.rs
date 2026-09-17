// SPDX-License-Identifier: GPL-3.0-or-later
//! Static backend registry: duplicate `BackendId` is `Err`, never a panic.

use crate::backend::Backend;
use crate::enums::BackendId;
use std::fmt::{Display, Formatter};

/// Registry of statically linked backends, keyed by [`BackendId`].
#[derive(Default)]
pub struct BackendRegistry {
    backends: Vec<&'static dyn Backend>,
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

    /// Register a statically linked backend. A duplicate [`BackendId`] is a
    /// panic-free `Err` and leaves the registry unchanged.
    pub fn register(&mut self, backend: &'static dyn Backend) -> Result<(), DuplicateBackend> {
        let id = backend.id();
        if self.backends.iter().any(|known| known.id() == id) {
            return Err(DuplicateBackend { backend: id });
        }
        self.backends.push(backend);
        Ok(())
    }

    /// All registered backends, in registration order.
    #[must_use]
    pub fn discover_all(&self) -> Vec<&'static dyn Backend> {
        self.backends.clone()
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
        };
        write!(f, "duplicate backend: {name}")
    }
}

impl std::error::Error for DuplicateBackend {}
