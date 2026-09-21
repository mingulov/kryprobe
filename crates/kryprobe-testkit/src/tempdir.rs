// SPDX-License-Identifier: GPL-3.0-or-later
//! RAII test scratch dirs (BP-L3): unique per guard, removed on drop.
//!
//! Replaces the hand-rolled `temp_dir().join(pid)` idiom (no cleanup,
//! pid+tag collisions under same-pid parallel tests). Deliberately
//! std-only: the repo's minimal-dependency policy holds for
//! dev-dependencies too when 30 lines suffice (`tempfile` would add
//! a supply-chain node for no extra safety here).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide construction counter: same-pid parallel tests
/// sharing a tag still get distinct dirs.
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// RAII test scratch dir: `temp_dir()/kryprobe-{tag}-{pid}-{n}`.
///
/// Created on construction (stale pre-existing content is cleared
/// first, so a SIGKILLed earlier run cannot poison this one);
/// removed on drop (best-effort) — including during unwinding, so a
/// failed assertion never leaks `/tmp` entries.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a fresh scratch dir for `tag`.
    pub fn named(tag: &str) -> std::io::Result<Self> {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("kryprobe-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)?;
        Ok(TempDir { path })
    }

    /// The scratch dir path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
