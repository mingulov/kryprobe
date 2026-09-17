// SPDX-License-Identifier: GPL-3.0-or-later
//! Observed-object references: file identity plus liveness state.

use serde::{Deserialize, Serialize};

/// Role of an observed object file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectRole {
    /// Target executable image.
    Executable,
    /// Shared library (for example a provider or PKCS#11 module).
    SharedLibrary,
    /// Kernel module or driver image.
    KernelModule,
    /// Role could not be determined.
    Unknown,
}

/// File identity of an observed object (device/inode/size/mtime + role).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectRef {
    /// Device holding the file.
    pub dev: u64,
    /// Inode number.
    pub ino: u64,
    /// File size in bytes.
    pub size: u64,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime: i64,
    /// Role of this object in the observation.
    pub role: ObjectRole,
}

/// Liveness of an [`ObjectRef`] as last verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectState {
    /// Re-verified identical since discovery.
    Verified,
    /// File identity changed since discovery.
    Changed,
    /// File no longer present.
    Deleted,
    /// Identity could not be pinned to one file.
    Ambiguous,
}
