// SPDX-License-Identifier: GPL-3.0-or-later
//! Stable session-scoped identities (CONTRACTS §1).
//!
//! Every ID renders as a `kind:value` string matching the envelope pattern
//! `^[a-z][a-z0-9_-]*:[A-Za-z0-9_.-]+$`, and serializes to that same string.
//! Parsing accepts canonical spellings only (no leading zeros).

use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// Rejection of a malformed `kind:value` ID string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdParseError {
    expected_kind: &'static str,
    found: String,
}

impl IdParseError {
    /// Describe what kind was expected and what text was found instead.
    #[must_use]
    pub fn new(expected_kind: &'static str, found: &str) -> Self {
        Self {
            expected_kind,
            found: found.to_owned(),
        }
    }
}

impl Display for IdParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid id: expected `{}:<int>`, found `{}`",
            self.expected_kind, self.found
        )
    }
}

impl std::error::Error for IdParseError {}

/// Define a `kind:value` ID type with [`IdParseError`] rejection, `Display`,
/// `FromStr`, and string-form serde impls.
#[macro_export]
macro_rules! define_id {
    ($name:ident, $inner:ty, $kind:literal) => {
        /// Opaque session-scoped identifier; displays as `kind:value`.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name($inner);

        impl $name {
            /// Wrap a raw identifier value.
            #[must_use]
            pub const fn new(value: $inner) -> Self {
                Self(value)
            }

            /// Unwrap the raw identifier value.
            #[must_use]
            pub const fn get(self) -> $inner {
                self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, concat!($kind, ":", "{}"), self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                let digits = match text.strip_prefix(concat!($kind, ":")) {
                    Some(digits) => digits,
                    None => return Err(IdParseError::new($kind, text)),
                };
                let shaped = !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit());
                // Canonical spelling only: `Display` never emits leading
                // zeros, so the parser rejects them (fail closed; `0`
                // itself stays valid).
                let canonical = digits.len() == 1 || !digits.starts_with('0');
                if !shaped || !canonical {
                    return Err(IdParseError::new($kind, text));
                }
                digits
                    .parse::<$inner>()
                    .map(Self)
                    .map_err(|_| IdParseError::new($kind, text))
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = <String as serde::Deserialize>::deserialize(deserializer)?;
                text.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

define_id!(SessionId, u128, "session");
define_id!(TargetId, u64, "target");
define_id!(ObjectId, u64, "object");
define_id!(ImplementationId, u64, "implementation");
define_id!(ObservationId, u64, "observation");
define_id!(CorrelationId, u64, "correlation");
define_id!(PlanGeneration, u32, "plan_generation");
define_id!(ProcessGeneration, u64, "process_generation");

/// Session-scoped observation ID issuer.
///
/// Backends must NOT mint IDs from private counters: two backends would
/// issue colliding `observation:N` values into one session. The runtime
/// owns one issuer per session and loans it through
/// [`DecodeContext`](crate::backend::DecodeContext); every decoded
/// observation takes the next value.
#[derive(Debug, Default)]
pub struct IdIssuer {
    next: std::sync::atomic::AtomicU64,
}

/// Session observation-ID space exhausted: all 2^64 IDs issued.
///
/// Fail closed: the caller decodes nothing, so no duplicate ID can alias
/// two observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdExhausted;

impl Display for IdExhausted {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "observation id space exhausted: 2^64 ids issued")
    }
}

impl std::error::Error for IdExhausted {}

impl IdIssuer {
    /// Issue the next session-scoped observation ID (1-based).
    ///
    /// Refuses with [`IdExhausted`] once `u64::MAX` is issued: the
    /// counter never wraps (wrapping would alias new observations to
    /// old IDs). Unreachable in practice — 2^64 issues — but fail-closed.
    pub fn issue(&self) -> Result<ObservationId, IdExhausted> {
        use std::sync::atomic::Ordering;
        // L5: uniqueness needs RMW atomicity (inherent), not a global
        // order — `AcqRel` publishes the increment to other issuers.
        match self
            .next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
        {
            // Success implies `prev < u64::MAX`, so `prev + 1` cannot overflow.
            Ok(prev) => Ok(ObservationId::new(prev + 1)),
            // At `u64::MAX` nothing is stored: the counter stays refused,
            // never wraps.
            Err(_) => Err(IdExhausted),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn issue_counts_from_one() {
        let issuer = IdIssuer::default();
        assert_eq!(issuer.issue(), Ok(ObservationId::new(1)));
        assert_eq!(issuer.issue(), Ok(ObservationId::new(2)));
        assert_eq!(issuer.issue(), Ok(ObservationId::new(3)));
    }

    #[test]
    fn issue_refuses_at_u64_max_without_wrapping() {
        let issuer = IdIssuer {
            next: AtomicU64::new(u64::MAX - 1),
        };
        assert_eq!(issuer.issue(), Ok(ObservationId::new(u64::MAX)));
        assert_eq!(issuer.issue(), Err(IdExhausted));
        // Stays refused: never wraps to 0 and re-issues old IDs.
        assert_eq!(issuer.issue(), Err(IdExhausted));
        assert_eq!(
            IdExhausted.to_string(),
            "observation id space exhausted: 2^64 ids issued"
        );
    }
}
