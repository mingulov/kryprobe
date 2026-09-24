// SPDX-License-Identifier: GPL-3.0-or-later
//! Backend identity (CONTRACTS §2).
//!
//! Wire spellings are exactly the `schemas/event-v0.schema.json` backend
//! strings. `Synthetic` is Rust-only (test harnesses) and never serializes,
//! mirroring `EvidencePhase::Succeeded`.

use kryprobe_abi::{BACKEND_KCRYPTO, BACKEND_OPENSSL, BACKEND_P11, BACKEND_SYNTHETIC};
use serde::{Deserialize, Serialize};

/// Backend producing an observation (CONTRACTS §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendId {
    /// PKCS#11 backend (`p11` on the wire). Compatibility-only: decodes
    /// legacy data and generic tests; no backend ships (ADR-0004).
    P11,
    /// OpenSSL backend (`openssl` on the wire). Reserved: no backend
    /// ships (ADR-0004); kept for wire stability and generic tests.
    OpenSsl,
    /// Kernel-crypto backend (`kcrypto` on the wire).
    KCrypto,
    /// Synthetic scripted backend. Never serialized.
    Synthetic,
}

const BACKEND_WIRE_STRS: [&str; 3] = ["p11", "openssl", "kcrypto"];

impl BackendId {
    /// BPF wire discriminator from [`kryprobe_abi`].
    #[must_use]
    pub const fn wire_id(self) -> u16 {
        match self {
            Self::P11 => BACKEND_P11,
            Self::OpenSsl => BACKEND_OPENSSL,
            Self::KCrypto => BACKEND_KCRYPTO,
            Self::Synthetic => BACKEND_SYNTHETIC,
        }
    }

    /// Wire spelling, or `None` for the internal `Synthetic` backend.
    #[must_use]
    pub const fn as_wire_str(self) -> Option<&'static str> {
        match self {
            Self::P11 => Some(BACKEND_WIRE_STRS[0]),
            Self::OpenSsl => Some(BACKEND_WIRE_STRS[1]),
            Self::KCrypto => Some(BACKEND_WIRE_STRS[2]),
            Self::Synthetic => None,
        }
    }

    /// Parse a wire spelling; `None` for anything else, including `synthetic`.
    #[must_use]
    pub fn from_wire_str(text: &str) -> Option<Self> {
        match text {
            "p11" => Some(Self::P11),
            "openssl" => Some(Self::OpenSsl),
            "kcrypto" => Some(Self::KCrypto),
            _ => None,
        }
    }
}

impl Serialize for BackendId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.as_wire_str() {
            Some(wire) => serializer.serialize_str(wire),
            None => Err(serde::ser::Error::custom(
                "defect: BackendId::Synthetic is internal and never serialized",
            )),
        }
    }
}

impl<'de> Deserialize<'de> for BackendId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_wire_str(&text)
            .ok_or_else(|| serde::de::Error::unknown_variant(&text, &BACKEND_WIRE_STRS))
    }
}
