// SPDX-License-Identifier: GPL-3.0-or-later
//! AEAD byte derivation: attempted vs terminal-success-qualified bytes
//! (P5 internal metadata contract v2 — amends the P3 contract v1 in
//! [`super::RequestMeta`] without touching its skcipher fields).
//!
//! Pure functions over submit-pinned scalars: the caller supplies the
//! entry-observed `cryptlen` (known — a submit with unknown cryptlen
//! carries no AEAD attempt row at all), `assoclen`, and `authsize`
//! (each independently unknown when its chase was unreadable), and
//! the derivation splits the attempt into direction-specific input,
//! payload, AAD, and tag populations. Terminal truth
//! ([`super::Terminal`]) then qualifies the succeeded subset: only a
//! zero-status terminal qualifies bytes, and unknown derivations
//! qualify zero — never a guessed split.
//!
//! Internal-only like the v1 contract: the report boundary (P6)
//! versions any public emission; until then these ride the reducer
//! as opaque facts.

use super::{OpDirection, Terminal};

/// One derived AEAD length: a known count, or an explicit unknown
/// with the reason (never a guessed zero, never a wrapped underflow).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadLen {
    /// Observed/derivable count (a valid zero stays `Known(0)` —
    /// an empty decrypt payload at input == tag length is data).
    Known(u32),
    /// The split is unknowable — see the reason.
    Unknown(AeadUnknown),
}

/// Why an AEAD length derived unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadUnknown {
    /// No authsize was captured (unreadable chase, or no successful
    /// setauthsize on the bound generation): the tag width — and
    /// hence any decrypt payload split — is unknowable.
    MissingAuthsize,
    /// The captured authsize is invalid (zero — no AEAD mode has a
    /// zero tag; the kernel rejects it): no split is expressible.
    InvalidAuthsize,
    /// The decrypt input is shorter than the tag: it cannot contain
    /// a payload. The input count stays known; only the split is
    /// unknown (an underflow wrap would fabricate ~4 GiB of payload).
    ShortInput {
        /// Observed input length.
        cryptlen: u32,
        /// Observed tag width.
        authsize: u32,
    },
    /// No assoclen was captured: the AAD count is unknowable.
    MissingAssoc,
}

/// Attempted AEAD bytes: the submit-observed split (attempt
/// population — terminal truth never rewrites it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadAttempt {
    /// Raw API input length (`cryptlen` at entry — always known:
    /// the caller forms no attempt row without it).
    pub input: AeadLen,
    /// Payload candidate: decrypt subtracts the tag (it rides inside
    /// the input); encrypt echoes the input (the tag is appended on
    /// output, outside the observed input).
    pub payload: AeadLen,
    /// Associated-data length (`assoclen` at entry).
    pub aad: AeadLen,
    /// Tag width (`authsize` — submit-chased, like `cryptlen`).
    pub tag: AeadLen,
}

/// Terminal-success-qualified AEAD bytes: the succeeded subset of an
/// attempt (plain counts — unknown derivations and non-success
/// terminals qualify zero, explicitly, never by guessing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AeadSuccess {
    /// Succeeded input bytes.
    pub input: u32,
    /// Succeeded payload bytes.
    pub payload: u32,
    /// Succeeded AAD bytes.
    pub aad: u32,
}

/// Derive the attempted split for one AEAD submit: `cryptlen` is the
/// entry-observed API input length (known — see the module docs),
/// `assoclen`/`authsize` the entry-observed scalars (`None` when
/// their chase was unreadable). Direction-specific: decrypt inputs
/// carry the tag inside (`payload = cryptlen - authsize`, checked —
/// a short input is [`AeadUnknown::ShortInput`], never a wrap);
/// encrypt inputs are pure payload. A missing/invalid authsize
/// leaves tag and decrypt-payload unknown, never guessed.
#[must_use]
pub fn derive_attempt(
    direction: OpDirection,
    cryptlen: u32,
    assoclen: Option<u32>,
    authsize: Option<u32>,
) -> AeadAttempt {
    let aad = match assoclen {
        Some(len) => AeadLen::Known(len),
        None => AeadLen::Unknown(AeadUnknown::MissingAssoc),
    };
    // Encrypt inputs are pure payload (the tag is appended on
    // output, outside the observed input): the payload echoes the
    // input whatever the tag validity. Decrypt inputs carry the tag
    // inside: the split needs a valid authsize and a long-enough
    // input, checked — never wrapped, never guessed.
    let payload = match direction {
        OpDirection::Encrypt => AeadLen::Known(cryptlen),
        OpDirection::Decrypt => match authsize {
            None => AeadLen::Unknown(AeadUnknown::MissingAuthsize),
            Some(0) => AeadLen::Unknown(AeadUnknown::InvalidAuthsize),
            Some(auth) => match cryptlen.checked_sub(auth) {
                Some(rest) => AeadLen::Known(rest),
                None => AeadLen::Unknown(AeadUnknown::ShortInput {
                    cryptlen,
                    authsize: auth,
                }),
            },
        },
    };
    let tag = match authsize {
        Some(auth) if auth != 0 => AeadLen::Known(auth),
        Some(_) => AeadLen::Unknown(AeadUnknown::InvalidAuthsize),
        None => AeadLen::Unknown(AeadUnknown::MissingAuthsize),
    };
    AeadAttempt {
        input: AeadLen::Known(cryptlen),
        payload,
        aad,
        tag,
    }
}

/// Qualify the succeeded subset of an attempt against its terminal
/// truth: a zero-status terminal (`Sync(0)`/`Callback(0)`) qualifies
/// each `Known` derivation (unknown derivations qualify zero — the
/// split was never expressible); any other terminal (nonzero status
/// like `-EBADMSG`, or [`Terminal::Unknown`]) qualifies zero across
/// all three populations. The attempt itself is untouched (attempted
/// vs succeeded stay separate populations).
#[must_use]
pub fn qualify_success(attempt: &AeadAttempt, terminal: Terminal) -> AeadSuccess {
    let success = matches!(terminal, Terminal::Sync(0) | Terminal::Callback(0));
    if !success {
        return AeadSuccess::default();
    }
    let known = |len: AeadLen| match len {
        AeadLen::Known(n) => n,
        AeadLen::Unknown(_) => 0,
    };
    AeadSuccess {
        input: known(attempt.input),
        payload: known(attempt.payload),
        aad: known(attempt.aad),
    }
}
