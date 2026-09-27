// SPDX-License-Identifier: GPL-3.0-or-later
//! AEAD lifecycle without ambiguous byte totals (P5/T10).
//!
//! Contract v2 derivation (A01–A03: direction-specific attempted vs
//! terminal-success-qualified input/payload/AAD/tag-size metadata)
//! plus the capture integration: failed-authsize epoch retention,
//! unknown-authsize payload, sync/async schedule parity, and
//! reconfiguration — all over v7 bytes through the production
//! [`SensorCore`] ingest.

use kryprobe_core::kcrypto::OpDirection;
use kryprobe_core::kcrypto::Terminal;
use kryprobe_core::kcrypto::aead::{AeadLen, derive_attempt, qualify_success};
use kryprobe_core::kcrypto::{LifecycleFamily, RequestMeta};
use kryprobe_privilege::kcrypto_lifecycle::sensor::SensorCore;

const SUBMIT: u8 = 1;
const RETURN: u8 = 2;
const CALLBACK: u8 = 3;
const AEAD_ENC: u16 = 5;
const AEAD_DEC: u16 = 6;
const CB_KXC: u16 = 4;
const TFM_ALLOCAEAD: u16 = 5;
const TFM_SETAUTHSIZE: u16 = 4;

/// One 112-byte v7 `LEdge` AEAD op edge (submit pins validity-gated
/// scalars + family + class-echoing direction; returns carry the
/// status only).
#[allow(clippy::too_many_arguments)]
fn aead_op(
    edge: u8,
    site: u16,
    key: u64,
    ts_ns: u64,
    status: i32,
    invoc: u64,
    tfm: u64,
    cryptlen: Option<u32>,
    req_flags: Option<u32>,
    assoclen: Option<u32>,
    authsize: Option<u32>,
    drv: &[u8],
) -> Vec<u8> {
    let mut out = vec![0u8; 112];
    out[0..2].copy_from_slice(&0x434cu16.to_le_bytes());
    out[2] = 7;
    out[3] = edge;
    out[4..6].copy_from_slice(&site.to_le_bytes());
    out[8..16].copy_from_slice(&key.to_le_bytes());
    out[16..24].copy_from_slice(&ts_ns.to_le_bytes());
    out[24..28].copy_from_slice(&status.to_le_bytes());
    if edge == SUBMIT {
        let mut mflags = 0u16;
        if let Some(c) = cryptlen {
            out[28..32].copy_from_slice(&c.to_le_bytes());
            mflags |= 0x01;
        }
        if let Some(f) = req_flags {
            out[48..52].copy_from_slice(&f.to_le_bytes());
            mflags |= 0x02;
        }
        if let Some(a) = assoclen {
            out[56..60].copy_from_slice(&a.to_le_bytes());
            mflags |= 0x04;
        }
        if let Some(a) = authsize {
            out[60..64].copy_from_slice(&a.to_le_bytes());
            mflags |= 0x08;
        }
        out[52] = 2;
        out[53] = if site == AEAD_ENC { 1 } else { 2 };
        out[54..56].copy_from_slice(&mflags.to_le_bytes());
        let n = drv.len().min(47);
        out[64..64 + n].copy_from_slice(&drv[..n]);
    }
    out[32..40].copy_from_slice(&invoc.to_le_bytes());
    out[40..48].copy_from_slice(&tfm.to_le_bytes());
    out
}

/// One 112-byte v1 `LTfm` edge (alloc-aead submit/return or
/// setauthsize submit/return twin).
#[allow(clippy::too_many_arguments)]
fn tfm_edge(
    edge: u8,
    site: u16,
    key: u64,
    ts_ns: u64,
    status: i32,
    aux: u32,
    aux2: u32,
    token: u64,
    name: &[u8],
) -> Vec<u8> {
    let mut out = vec![0u8; 112];
    out[0..2].copy_from_slice(&0x544cu16.to_le_bytes());
    out[2] = 1;
    out[3] = edge;
    out[4..6].copy_from_slice(&site.to_le_bytes());
    out[8..16].copy_from_slice(&key.to_le_bytes());
    out[16..24].copy_from_slice(&ts_ns.to_le_bytes());
    out[24..28].copy_from_slice(&status.to_le_bytes());
    out[28..32].copy_from_slice(&aux.to_le_bytes());
    out[32..36].copy_from_slice(&aux2.to_le_bytes());
    out[40..48].copy_from_slice(&token.to_le_bytes());
    let n = name.len().min(63);
    out[48..48 + n].copy_from_slice(&name[..n]);
    out
}

/// One 112-byte v7 `LEdge` fixture-callback half (accepted async
/// schedule: key + status + ts, invoc 0, zero metadata).
fn cb_kxc(key: u64, ts_ns: u64, status: i32) -> Vec<u8> {
    let mut out = vec![0u8; 112];
    out[0..2].copy_from_slice(&0x434cu16.to_le_bytes());
    out[2] = 7;
    out[3] = CALLBACK;
    out[4..6].copy_from_slice(&CB_KXC.to_le_bytes());
    out[8..16].copy_from_slice(&key.to_le_bytes());
    out[16..24].copy_from_slice(&ts_ns.to_le_bytes());
    out[24..28].copy_from_slice(&status.to_le_bytes());
    out
}

/// Ingest an alloc-aead + successful setauthsize(16) on `frontend`
/// (the configured-generation preamble every byte test shares).
fn configure_aead(core: &mut SensorCore, frontend: u64) {
    let records = vec![
        tfm_edge(SUBMIT, TFM_ALLOCAEAD, 0, 10, 0, 0, 0, 0x5000, b"gcm(aes)"),
        tfm_edge(
            RETURN,
            TFM_ALLOCAEAD,
            frontend,
            20,
            0,
            0,
            0,
            0x5000,
            b"gcm-aesni",
        ),
        tfm_edge(SUBMIT, TFM_SETAUTHSIZE, frontend, 30, 0, 16, 0, 0x5002, b""),
        tfm_edge(RETURN, TFM_SETAUTHSIZE, 0, 40, 0, 0, 0, 0x5002, b""),
    ];
    core.ingest_records(&records);
}

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

/// Contract v2 shape: the AEAD family exists, and skcipher submits
/// carry NO AEAD extension (the extension rides AEAD submits only —
/// a skcipher record with AEAD lengths would be a mislabeled
/// population).
#[test]
fn skcipher_submits_carry_no_aead_extension() {
    assert_ne!(
        LifecycleFamily::Aead,
        LifecycleFamily::Skcipher,
        "AEAD is its own family, never a relabeled skcipher"
    );
    let mut core = SensorCore::new(16, 16, 16, 8, 8, true);
    let key = 0xabc_u64;
    let frontend = 0xFFFF_8880_0000_1000_u64;
    let mut submit = vec![0u8; 112];
    submit[0..2].copy_from_slice(&0x434cu16.to_le_bytes());
    submit[2] = 7;
    submit[3] = 1;
    submit[4..6].copy_from_slice(&1u16.to_le_bytes());
    submit[8..16].copy_from_slice(&key.to_le_bytes());
    submit[16..24].copy_from_slice(&100u64.to_le_bytes());
    submit[28..32].copy_from_slice(&16u32.to_le_bytes());
    submit[32..40].copy_from_slice(&0x4000u64.to_le_bytes());
    submit[40..48].copy_from_slice(&frontend.to_le_bytes());
    submit[48..52].copy_from_slice(&0u32.to_le_bytes());
    submit[52] = 1;
    submit[53] = 1;
    submit[54..56].copy_from_slice(&0x03u16.to_le_bytes());
    let mut ret = vec![0u8; 112];
    ret[0..2].copy_from_slice(&0x434cu16.to_le_bytes());
    ret[2] = 7;
    ret[3] = 2;
    ret[4..6].copy_from_slice(&1u16.to_le_bytes());
    ret[8..16].copy_from_slice(&key.to_le_bytes());
    ret[16..24].copy_from_slice(&105u64.to_le_bytes());
    ret[32..40].copy_from_slice(&0x4000u64.to_le_bytes());
    assert_eq!(core.ingest_records(&[submit, ret]), 1);
    let done = core.take_completed();
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].meta.family, LifecycleFamily::Skcipher);
    assert_eq!(done[0].meta.aead, None);
    // The extension struct carries the two AEAD scalars, each
    // independently unknown-capable.
    let meta = RequestMeta {
        family: LifecycleFamily::Aead,
        direction: OpDirection::Decrypt,
        cryptlen: Some(1040),
        req_flags: Some(0),
        epoch: Some(1),
        aead: Some(kryprobe_core::kcrypto::AeadMeta {
            assoclen: Some(32),
            authsize: Some(16),
        }),
    };
    assert_eq!(meta.aead.unwrap().assoclen, Some(32));
    assert_eq!(meta.aead.unwrap().authsize, Some(16));
}

/// A failed setauthsize never replaces the prior successful epoch:
/// alloc-aead + setauthsize(16) ok pins epoch 1; a failing
/// setauthsize(64) records (configs + errno) without bumping; the
/// next AEAD op pins epoch 1 with the submit-chased authsize 16.
#[test]
fn failed_authsize_retains_prior_epoch() {
    let mut core = SensorCore::new(16, 16, 16, 8, 8, true);
    let frontend = 0xFFFF_8880_0000_1000_u64;
    configure_aead(&mut core, frontend);
    // Failing reconfig (EINVAL): records, never bumps.
    let records = vec![
        tfm_edge(SUBMIT, TFM_SETAUTHSIZE, frontend, 50, 0, 64, 0, 0x5004, b""),
        tfm_edge(RETURN, TFM_SETAUTHSIZE, 0, 60, -22, 0, 0, 0x5004, b""),
    ];
    core.ingest_records(&records);
    let gens = core.tfm().generations();
    assert_eq!(gens.len(), 1);
    assert_eq!(gens[0].epoch, 1, "failed config never bumps the epoch");
    assert_eq!(gens[0].configs, 2);
    assert_eq!(gens[0].last_config_errno, -22);
    // The next op pins the retained epoch + the submit-chased tag width.
    let key = 0xabc_u64;
    let records = vec![
        aead_op(
            SUBMIT,
            AEAD_DEC,
            key,
            100,
            0,
            0x4000,
            frontend,
            Some(1040),
            Some(0),
            Some(32),
            Some(16),
            b"gcm-aesni",
        ),
        aead_op(
            RETURN, AEAD_DEC, key, 150, 0, 0x4000, 0, None, None, None, None, b"",
        ),
    ];
    assert_eq!(core.ingest_records(&records), 1);
    let done = core.take_completed();
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].meta.family, LifecycleFamily::Aead);
    assert_eq!(done[0].meta.epoch, Some(1));
    let aead = done[0]
        .meta
        .aead
        .expect("AEAD submit carries the extension");
    assert_eq!((aead.assoclen, aead.authsize), (Some(32), Some(16)));
}

/// Missing authsize makes the derived payload unknown: the submit
/// chased cryptlen + assoclen but the tag-width chase was
/// unreadable, so the record carries `authsize: None` and the
/// derivation yields an explicit unknown — never a guessed split.
#[test]
fn unknown_authsize_has_unknown_payload() {
    let mut core = SensorCore::new(16, 16, 16, 8, 8, true);
    let frontend = 0xFFFF_8880_0000_1000_u64;
    configure_aead(&mut core, frontend);
    let key = 0xabc_u64;
    let records = vec![
        aead_op(
            SUBMIT,
            AEAD_DEC,
            key,
            100,
            0,
            0x4000,
            frontend,
            Some(1040),
            Some(0),
            Some(32),
            None,
            b"gcm-aesni",
        ),
        aead_op(
            RETURN, AEAD_DEC, key, 150, 0, 0x4000, 0, None, None, None, None, b"",
        ),
    ];
    assert_eq!(core.ingest_records(&records), 1);
    let done = core.take_completed();
    assert_eq!(done.len(), 1);
    let aead = done[0]
        .meta
        .aead
        .expect("AEAD submit carries the extension");
    assert_eq!(aead.assoclen, Some(32));
    assert_eq!(aead.authsize, None);
    let attempt = derive_attempt(
        done[0].meta.direction,
        done[0].meta.cryptlen.expect("cryptlen pinned"),
        aead.assoclen,
        aead.authsize,
    );
    assert!(matches!(attempt.payload, AeadLen::Unknown(_)));
    // Even terminal success qualifies zero payload (the split was
    // never expressible) while the known input still qualifies.
    let ok = qualify_success(&attempt, done[0].terminal);
    assert_eq!((ok.input, ok.payload, ok.aad), (1040, 0, 32));
}

/// The A01 shape end to end over sync bytes: decrypt 1040/32/16 →
/// attempted payload 1024 qualified in full on terminal success;
/// the EBADMSG leg qualifies zero with the attempt untouched.
#[test]
fn aead_decrypt_1040_flow_qualifies_success_bytes() {
    let mut core = SensorCore::new(16, 16, 16, 8, 8, true);
    let frontend = 0xFFFF_8880_0000_1000_u64;
    configure_aead(&mut core, frontend);
    let submit = |key: u64, ts: u64, invoc: u64| {
        aead_op(
            SUBMIT,
            AEAD_DEC,
            key,
            ts,
            0,
            invoc,
            frontend,
            Some(1040),
            Some(0),
            Some(32),
            Some(16),
            b"gcm-aesni",
        )
    };
    let records = vec![
        submit(0xabc, 100, 0x4000),
        aead_op(
            RETURN, AEAD_DEC, 0xabc, 150, 0, 0x4000, 0, None, None, None, None, b"",
        ),
        submit(0xabd, 200, 0x4002),
        aead_op(
            RETURN,
            AEAD_DEC,
            0xabd,
            250,
            -libc::EBADMSG,
            0x4002,
            0,
            None,
            None,
            None,
            None,
            b"",
        ),
    ];
    assert_eq!(core.ingest_records(&records), 2);
    let done = core.take_completed();
    assert_eq!(done.len(), 2);
    for rec in &done {
        assert_eq!(rec.meta.family, LifecycleFamily::Aead);
        assert_eq!(rec.meta.epoch, Some(1));
    }
    let attempt_of = |rec: &kryprobe_core::kcrypto::RequestRecord| {
        let aead = rec.meta.aead.expect("AEAD extension");
        derive_attempt(
            rec.meta.direction,
            rec.meta.cryptlen.expect("cryptlen"),
            aead.assoclen,
            aead.authsize,
        )
    };
    // Success leg: full qualification.
    assert_eq!(done[0].terminal, Terminal::Sync(0));
    let ok = qualify_success(&attempt_of(&done[0]), done[0].terminal);
    assert_eq!((ok.input, ok.payload, ok.aad), (1040, 1024, 32));
    // Bad-tag leg: zero success, attempt intact.
    assert_eq!(done[1].terminal, Terminal::Sync(-libc::EBADMSG));
    let failed = qualify_success(&attempt_of(&done[1]), done[1].terminal);
    assert_eq!((failed.input, failed.payload, failed.aad), (0, 0, 0));
    assert_eq!(attempt_of(&done[1]).payload, AeadLen::Known(1024));
}

/// Accepted async schedule parity: the same AEAD decrypt through
/// submit + `-EINPROGRESS` + fixture callback(0) completes
/// `Callback(0)` with byte-identical meta to the sync leg (native
/// results agree across schedules — the derivation never sees
/// which schedule ran).
#[test]
fn aead_async_schedule_matches_sync() {
    let mut core = SensorCore::new(16, 16, 16, 8, 8, true);
    let frontend = 0xFFFF_8880_0000_1000_u64;
    configure_aead(&mut core, frontend);
    let submit = aead_op(
        SUBMIT,
        AEAD_DEC,
        0xabc,
        100,
        0,
        0x4000,
        frontend,
        Some(1040),
        Some(0),
        Some(32),
        Some(16),
        b"gcm-aesni",
    );
    let records = vec![
        submit,
        aead_op(
            RETURN, AEAD_DEC, 0xabc, 150, -115, 0x4000, 0, None, None, None, None, b"",
        ),
        cb_kxc(0xabc, 200, 0),
    ];
    assert_eq!(core.ingest_records(&records), 1);
    let done = core.take_completed();
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].terminal, Terminal::Callback(0));
    assert_eq!(done[0].meta.family, LifecycleFamily::Aead);
    assert_eq!(done[0].meta.epoch, Some(1));
    assert_eq!(done[0].meta.cryptlen, Some(1040));
    let aead = done[0].meta.aead.expect("AEAD extension");
    assert_eq!((aead.assoclen, aead.authsize), (Some(32), Some(16)));
    let attempt = derive_attempt(
        done[0].meta.direction,
        done[0].meta.cryptlen.expect("cryptlen"),
        aead.assoclen,
        aead.authsize,
    );
    let ok = qualify_success(&attempt, done[0].terminal);
    assert_eq!((ok.input, ok.payload, ok.aad), (1040, 1024, 32));
}

/// Reconfiguration pins the new epoch on later ops only: ops under
/// epoch 1 keep epoch 1 after a successful setauthsize(8) bumps to
/// epoch 2; later ops pin epoch 2 (submit-pinned eras, never
/// rewritten history).
#[test]
fn aead_reconfiguration_pins_new_epoch() {
    let mut core = SensorCore::new(16, 16, 16, 8, 8, true);
    let frontend = 0xFFFF_8880_0000_1000_u64;
    configure_aead(&mut core, frontend);
    let submit = |key: u64, ts: u64, invoc: u64, authsize: Option<u32>| {
        aead_op(
            SUBMIT,
            AEAD_DEC,
            key,
            ts,
            0,
            invoc,
            frontend,
            Some(1040),
            Some(0),
            Some(32),
            authsize,
            b"gcm-aesni",
        )
    };
    let ret = |key: u64, ts: u64, invoc: u64| {
        aead_op(
            RETURN, AEAD_DEC, key, ts, 0, invoc, 0, None, None, None, None, b"",
        )
    };
    // Op under epoch 1 (width 16), then a successful reconfig to
    // authsize 8, then an op under epoch 2 (submit chases the new
    // width 8 off the live frontend).
    core.ingest_records(&[
        submit(0xabc, 100, 0x4000, Some(16)),
        ret(0xabc, 150, 0x4000),
    ]);
    core.ingest_records(&[
        tfm_edge(SUBMIT, TFM_SETAUTHSIZE, frontend, 160, 0, 8, 0, 0x5004, b""),
        tfm_edge(RETURN, TFM_SETAUTHSIZE, 0, 170, 0, 0, 0, 0x5004, b""),
    ]);
    core.ingest_records(&[submit(0xabd, 200, 0x4002, Some(8)), ret(0xabd, 250, 0x4002)]);
    let done = core.take_completed();
    assert_eq!(done.len(), 2);
    assert_eq!(done[0].meta.epoch, Some(1));
    assert_eq!(done[0].meta.aead.expect("extension").authsize, Some(16));
    assert_eq!(done[1].meta.epoch, Some(2));
    assert_eq!(done[1].meta.aead.expect("extension").authsize, Some(8));
}
