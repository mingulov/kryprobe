// SPDX-License-Identifier: GPL-3.0-or-later
//! Typed backend errors (CONTRACTS §14).
//!
//! Every variant carries a static reason plus optional detail. `Internal` is
//! a KryProbe defect and always renders with a `defect:` marker.

use std::fmt::{Display, Formatter};

macro_rules! define_reason {
    ($name:ident, $label:literal) => {
        #[doc = concat!("Reason for a `", $label, "` backend error.")]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            /// Static machine-stable reason string.
            pub reason: &'static str,
            /// Optional human context; never secrets or target bytes.
            pub detail: Option<String>,
        }

        impl $name {
            /// Reason without additional detail.
            #[must_use]
            pub const fn new(reason: &'static str) -> Self {
                Self {
                    reason,
                    detail: None,
                }
            }

            /// Reason with human-readable context.
            #[must_use]
            pub fn with_detail(reason: &'static str, detail: &str) -> Self {
                Self {
                    reason,
                    detail: Some(detail.to_owned()),
                }
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                match &self.detail {
                    Some(detail) => {
                        write!(f, concat!($label, ": {} ({})"), self.reason, detail)
                    }
                    None => write!(f, concat!($label, ": {}"), self.reason),
                }
            }
        }
    };
}

define_reason!(UnsupportedReason, "unsupported");
define_reason!(DeniedReason, "denied");
define_reason!(UnstableReason, "unstable");
define_reason!(BudgetReason, "exhausted");
define_reason!(SafetyReason, "unsafe");
define_reason!(AmbiguityReason, "ambiguous");
define_reason!(InputReason, "corrupt_input");
define_reason!(InternalError, "defect: internal");

/// Typed backend failure (CONTRACTS §14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    /// Declared boundary is not supported.
    Unsupported(UnsupportedReason),
    /// Operation was refused by an authority.
    Denied(DeniedReason),
    /// Target state changed under the observer.
    Unstable(UnstableReason),
    /// A budget counter ran out.
    Exhausted(BudgetReason),
    /// Proceeding would violate a safety rule.
    Unsafe(SafetyReason),
    /// Identity or attribution is ambiguous.
    Ambiguous(AmbiguityReason),
    /// Input failed validation.
    CorruptInput(InputReason),
    /// KryProbe defect; never silently partial.
    Internal(InternalError),
}

impl Display for BackendError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(reason) => Display::fmt(reason, f),
            Self::Denied(reason) => Display::fmt(reason, f),
            Self::Unstable(reason) => Display::fmt(reason, f),
            Self::Exhausted(reason) => Display::fmt(reason, f),
            Self::Unsafe(reason) => Display::fmt(reason, f),
            Self::Ambiguous(reason) => Display::fmt(reason, f),
            Self::CorruptInput(reason) => Display::fmt(reason, f),
            Self::Internal(reason) => Display::fmt(reason, f),
        }
    }
}

impl std::error::Error for BackendError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_variant_reason_and_detail() {
        let err = BackendError::Denied(DeniedReason::with_detail("yama_scope", "scope 3"));
        assert_eq!(err.to_string(), "denied: yama_scope (scope 3)");
        let err = BackendError::Exhausted(BudgetReason::new("targets"));
        assert_eq!(err.to_string(), "exhausted: targets");
    }

    #[test]
    fn internal_display_carries_defect_marker() {
        let err = BackendError::Internal(InternalError::new("nil_generation"));
        assert!(err.to_string().contains("defect:"), "{err}");
        let err = BackendError::Internal(InternalError::with_detail("x", "y"));
        assert!(err.to_string().contains("defect:"), "{err}");
    }
}
