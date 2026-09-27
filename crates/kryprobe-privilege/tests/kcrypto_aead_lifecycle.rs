// SPDX-License-Identifier: GPL-3.0-or-later
//! AEAD lifecycle without ambiguous byte totals (P5/T10).
//!
//! RED phase (A01–A03, before capture changes): direction-specific
//! attempted vs terminal-success-qualified input/payload/AAD/tag-size
//! metadata. These tests drive the AEAD metadata contract v2
//! derivation (`kryprobe_core::kcrypto::aead`) fed by submit-pinned
//! scalars; the capture slices (wire v7, tracker, sensor, fixture)
//! land after this RED checkpoint.

use kryprobe_core::kcrypto::OpDirection;
use kryprobe_core::kcrypto::Terminal;
use kryprobe_core::kcrypto::aead::{AeadLen, derive_attempt, qualify_success};

/// A01: decrypt cryptlen 1040, authsize 16, assoclen 32 → raw input
/// 1040, payload candidate 1024, AAD 32. The tag rides inside the
/// decrypt input, so the payload candidate subtracts it; AAD is the
/// associated-data length, independent of the payload.
#[test]
fn decrypt_1040_tag16_aad32_payload1024() {
    let attempt = derive_attempt(OpDirection::Decrypt, 1040, Some(32), Some(16));
    assert_eq!(attempt.input, AeadLen::Known(1040));
    assert_eq!(attempt.payload, AeadLen::Known(1024));
    assert_eq!(attempt.aad, AeadLen::Known(32));
    assert_eq!(attempt.tag, AeadLen::Known(16));
    // Encrypt mirrors with the tag OUTSIDE the input: payload equals
    // input, never input-minus-tag.
    let enc = derive_attempt(OpDirection::Encrypt, 1024, Some(32), Some(16));
    assert_eq!(enc.input, AeadLen::Known(1024));
    assert_eq!(enc.payload, AeadLen::Known(1024));
    assert_eq!(enc.aad, AeadLen::Known(32));
    assert_eq!(enc.tag, AeadLen::Known(16));
}

/// A02: an invalid tag ends `EBADMSG` and contributes ZERO successful
/// payload — while the ATTEMPTED payload stays 1024. Attempted bytes
/// (submit-observed) and succeeded bytes (terminal-success-qualified)
/// are separate populations, never one ambiguous total.
#[test]
fn bad_tag_does_not_add_success_bytes() {
    let attempt = derive_attempt(OpDirection::Decrypt, 1040, Some(32), Some(16));
    assert_eq!(attempt.payload, AeadLen::Known(1024));
    let failed = qualify_success(&attempt, Terminal::Sync(-libc::EBADMSG));
    assert_eq!(failed.payload, 0);
    assert_eq!(failed.input, 0);
    assert_eq!(failed.aad, 0);
    // Same shape through the async schedule: a terminal callback
    // with EBADMSG qualifies nothing either.
    let failed_cb = qualify_success(&attempt, Terminal::Callback(-libc::EBADMSG));
    assert_eq!(failed_cb.payload, 0);
    // Positive control: terminal success qualifies the full attempt.
    let ok = qualify_success(&attempt, Terminal::Sync(0));
    assert_eq!(ok.payload, 1024);
    assert_eq!(ok.input, 1040);
    assert_eq!(ok.aad, 32);
    let ok_cb = qualify_success(&attempt, Terminal::Callback(0));
    assert_eq!(ok_cb.payload, 1024);
    // Truthless terminals qualify nothing, never a guessed zero-as-data.
    let unknown = qualify_success(&attempt, Terminal::Unknown);
    assert_eq!(unknown.payload, 0);
    assert_eq!(unknown.input, 0);
    assert_eq!(unknown.aad, 0);
}

/// A03: short input and invalid authsize are explicit error/unknown —
/// never a u32 underflow wrap, never a guessed zero payload. A
/// decrypt input shorter than the tag cannot contain a payload; a
/// missing authsize leaves the payload unknown (the tag width is
/// unknowable, so no candidate is expressible).
#[test]
fn short_cryptlen_does_not_underflow() {
    // Decrypt input shorter than the tag: input known, payload unknown.
    let short = derive_attempt(OpDirection::Decrypt, 8, Some(32), Some(16));
    assert_eq!(short.input, AeadLen::Known(8));
    assert!(matches!(short.payload, AeadLen::Unknown(_)));
    assert_eq!(short.aad, AeadLen::Known(32));
    // Boundary: input exactly the tag length → empty payload, known zero.
    let edge = derive_attempt(OpDirection::Decrypt, 16, Some(0), Some(16));
    assert_eq!(edge.payload, AeadLen::Known(0));
    // Missing authsize: payload unknown, never guessed.
    let no_auth = derive_attempt(OpDirection::Decrypt, 1040, Some(32), None);
    assert_eq!(no_auth.input, AeadLen::Known(1040));
    assert!(matches!(no_auth.payload, AeadLen::Unknown(_)));
    assert!(matches!(no_auth.tag, AeadLen::Unknown(_)));
    // Invalid (zero) authsize: explicit unknown, never 1040-minus-0
    // masquerading as a real payload split.
    let zero_auth = derive_attempt(OpDirection::Decrypt, 1040, Some(32), Some(0));
    assert!(matches!(zero_auth.payload, AeadLen::Unknown(_)));
    // Unknown derivations qualify zero success bytes without panic.
    let q = qualify_success(&short, Terminal::Sync(0));
    assert_eq!(q.payload, 0);
    assert_eq!(q.input, 8);
}
