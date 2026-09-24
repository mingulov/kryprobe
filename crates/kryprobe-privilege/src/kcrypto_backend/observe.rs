// SPDX-License-Identifier: GPL-3.0-or-later
//! D8 decode tables (1A-M10): snapshot rows to observations.

use super::WhoSnapshot;

/// Payload note on `UNOBSERVED` rows (unreachable-by-construction: only the
/// void destroy path carries this class, and it emits no rows).
const UNOBSERVED_NOTE: &str = "unobserved: void return carries no result class (destroy path)";

use crate::kallsyms::{SymTable, symbolize_with};
use kryprobe_abi::kcrypto_agg::{
    KAgg, KCTL_IDENT, KCTL_OVERFLOW, KCTX_KTHREAD, KCTX_PROC, KCTX_SOFTIRQ, KCTX_UNKNOWN, KCtl,
    KFAM_AEAD, KFAM_AHASH, KFAM_ANY, KFAM_SHASH, KFAM_SK, KOP_ALLOC, KOP_DEC, KOP_DESTROY,
    KOP_DIGEST, KOP_ENC, KOP_FINUP, KRES_ERR, KRES_OK, KRES_QUEUED, KRES_UNOBSERVED, VAgg,
    kctl_unpack_lens, kh_of,
};
use kryprobe_core::enums::{BackendId, CallKind, EvidencePhase, OperationClass};
use kryprobe_core::evidence::{
    IntegrityRef, NativeObservation, NativeResult, SafeTextId,
    payload_keys::{CAPTURE_API_RETURNS, COUNT_API_INVOCATION_RETURN, COVERAGE_UNOBSERVED},
};
use kryprobe_core::ids::ObservationId;
use serde_json::json;

// ---------------------------------------------------------------------------
// D8 decode tables (exact).
// ---------------------------------------------------------------------------

/// `(fam, op) → symbol`: the 9 D8 rows; `None` is honest-unknown (ANY+exec
/// and other live-impossible combos carry no symbol — the inventory marker
/// keeps them visible, never silent).
pub(crate) fn symbol_for(fam: u8, op: u8) -> Option<&'static str> {
    match op {
        KOP_ALLOC => Some("crypto_alloc_tfm_node"),
        KOP_DESTROY => Some("crypto_destroy_tfm"),
        KOP_ENC if fam == KFAM_SK => Some("crypto_skcipher_encrypt"),
        KOP_DEC if fam == KFAM_SK => Some("crypto_skcipher_decrypt"),
        KOP_ENC if fam == KFAM_AEAD => Some("crypto_aead_encrypt"),
        KOP_DEC if fam == KFAM_AEAD => Some("crypto_aead_decrypt"),
        KOP_DIGEST if fam == KFAM_AHASH => Some("crypto_ahash_digest"),
        KOP_DIGEST if fam == KFAM_SHASH => Some("crypto_shash_digest"),
        KOP_FINUP if fam == KFAM_SHASH => Some("crypto_shash_finup"),
        _ => None,
    }
}

/// `op → (call_kind, phase)`: ALLOC initializes (Selected), exec ops
/// complete on a terminal class else stay entered, DESTROY is the mapped
/// unreachable arm (unknown, Returned). Out-of-range ops degrade to
/// (unknown, Entered) — live-impossible (the BPF writes 1–6), never crash.
fn op_call_phase(op: u8, res: u8) -> (CallKind, EvidencePhase) {
    let terminal = res == KRES_OK || res == KRES_ERR;
    let entered_or_completed = if terminal {
        EvidencePhase::Completed
    } else {
        EvidencePhase::Entered
    };
    match op {
        KOP_ALLOC => (CallKind::Initialization, EvidencePhase::Selected),
        KOP_ENC | KOP_DEC | KOP_DIGEST => (CallKind::Operation, entered_or_completed),
        KOP_FINUP => (CallKind::Finalization, entered_or_completed),
        KOP_DESTROY => (CallKind::Unknown, EvidencePhase::Returned),
        _ => (CallKind::Unknown, EvidencePhase::Entered),
    }
}

/// `res → status`: canonical representatives (D9 — the sensor counts result
/// classes, not codes). Out-of-range classes degrade to 0 like UNOBSERVED.
fn status_for_res(res: u8) -> i32 {
    match res {
        KRES_OK => 0,
        KRES_ERR => -libc::EIO,
        KRES_QUEUED => -libc::EINPROGRESS,
        _ => 0,
    }
}

/// `op → operation class`: the frozen-schema 13-variant mapping for the six
/// kcrypto ops (transform lifecycle is key management; anything else is
/// unknown, never guessed).
fn class_for_op(op: u8) -> OperationClass {
    match op {
        KOP_ENC => OperationClass::Encrypt,
        KOP_DEC => OperationClass::Decrypt,
        KOP_DIGEST | KOP_FINUP => OperationClass::Digest,
        KOP_ALLOC | KOP_DESTROY => OperationClass::KeyManagement,
        _ => OperationClass::Unknown,
    }
}

fn family_name(fam: u8) -> &'static str {
    match fam {
        KFAM_ANY => "any",
        KFAM_SK => "skcipher",
        KFAM_AEAD => "aead",
        KFAM_AHASH => "ahash",
        KFAM_SHASH => "shash",
        _ => "unknown",
    }
}

fn op_name(op: u8) -> &'static str {
    match op {
        KOP_ALLOC => "alloc",
        KOP_DESTROY => "destroy",
        KOP_ENC => "encrypt",
        KOP_DEC => "decrypt",
        KOP_DIGEST => "digest",
        KOP_FINUP => "finup",
        _ => "unknown",
    }
}

fn result_name(res: u8) -> &'static str {
    match res {
        KRES_OK => "ok",
        KRES_ERR => "error",
        KRES_QUEUED => "queued",
        KRES_UNOBSERVED => "unobserved",
        _ => "unknown",
    }
}

/// `ctx → payload.context` (D8 verbatim spellings).
fn context_name(ctx: u8) -> &'static str {
    match ctx {
        KCTX_PROC => "process",
        KCTX_KTHREAD => "kthread",
        KCTX_SOFTIRQ => "softirq",
        KCTX_UNKNOWN => "unknown",
        _ => "unknown",
    }
}

/// `KCtl.val0` head unpack: the exact inverse of `kctl_pack_head`
/// (`fam | op<<8 | res<<16 | ctx<<24`).
pub(crate) fn unpack_head(val0: u64) -> (u8, u8, u8, u8) {
    (
        (val0 & 0xff) as u8,
        ((val0 >> 8) & 0xff) as u8,
        ((val0 >> 16) & 0xff) as u8,
        ((val0 >> 24) & 0xff) as u8,
    )
}

/// NUL-truncated kernel name from raw words (lossy: kernel names are ASCII;
/// empty on the alloc-path zero driver — never fabricated).
pub(crate) fn name_from_words(words: &[u64; 16]) -> String {
    let mut bytes = [0u8; 128];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Agg row → observation: the full D8 mapping. ANY-family rows force the
/// inventory shape (Selected / `execution: "unsupported"`); everything else
/// follows the op/res tables with identity in `backend_payload`.
pub(crate) fn observation_for_agg(
    kagg: &KAgg,
    vagg: &VAgg,
    id: ObservationId,
) -> NativeObservation {
    let (fam, op, res, ctx) = (kagg.fam(), kagg.op(), kagg.res(), kagg.ctx());
    let inventory = fam == KFAM_ANY;
    let (call_kind, mut phase) = op_call_phase(op, res);
    if inventory {
        phase = EvidencePhase::Selected;
    }
    // K5: the row hash (shared FNV-1a via `kryprobe-abi`, same bytes the
    // BPF hashed) so who-rows join; latency buckets pass through verbatim.
    let key_hash = kh_of(fam, op, res, ctx, &kagg.alg(), &kagg.drv());
    let mut payload = json!({
        "row": "agg",
        "key_hash": key_hash,
        "family": family_name(fam),
        "op": op_name(op),
        "result": result_name(res),
        "algorithm": name_from_words(&kagg.alg()),
        "driver": name_from_words(&kagg.drv()),
        "context": context_name(ctx),
        "counts": {"calls": vagg.calls, "ok": vagg.ok, "errors": vagg.errors, "queued": vagg.queued},
        "bytes": vagg.bytes,
        "lat": vagg.lat,
        "window": {"first_ns": vagg.first_ns, "last_ns": vagg.last_ns},
        "status_canonical": true,
        "capture_profile": CAPTURE_API_RETURNS,
        "count_unit": COUNT_API_INVOCATION_RETURN,
        "completion_coverage": COVERAGE_UNOBSERVED,
    });
    if inventory {
        payload["execution"] = json!("unsupported");
    }
    if res == KRES_UNOBSERVED {
        payload["result_note"] = json!(UNOBSERVED_NOTE);
    }
    NativeObservation {
        id,
        backend: BackendId::KCrypto,
        target: None,
        object: None,
        implementation: None,
        phase,
        call_kind,
        operation_class: class_for_op(op),
        native_name: symbol_for(fam, op).and_then(SafeTextId::new),
        native_code: None,
        native_result: NativeResult::KCrypto {
            status: status_for_res(res),
        },
        started_ns: Some(vagg.first_ns),
        ended_ns: Some(vagg.last_ns),
        correlation: None,
        integrity: IntegrityRef::new(0),
        backend_payload: payload,
    }
}

/// Totals row → observation: the aggregate-completion carrier. Status 0 is
/// the READ verdict (KTOT landed intact), not an op verdict — per-class
/// outcomes ride the payload counts, and K3 renders classes, never codes.
pub(crate) fn observation_for_totals(vagg: &VAgg, id: ObservationId) -> NativeObservation {
    NativeObservation {
        id,
        backend: BackendId::KCrypto,
        target: None,
        object: None,
        implementation: None,
        phase: EvidencePhase::Completed,
        call_kind: CallKind::Unknown,
        operation_class: OperationClass::Unknown,
        native_name: None,
        native_code: None,
        native_result: NativeResult::KCrypto { status: 0 },
        started_ns: Some(vagg.first_ns),
        ended_ns: Some(vagg.last_ns),
        correlation: None,
        integrity: IntegrityRef::new(0),
        backend_payload: json!({
            "row": "totals",
            "counts": {"calls": vagg.calls, "ok": vagg.ok, "errors": vagg.errors, "queued": vagg.queued},
            "bytes": vagg.bytes,
            "window": {"first_ns": vagg.first_ns, "last_ns": vagg.last_ns},
            "status_canonical": true,
            "capture_profile": CAPTURE_API_RETURNS,
            "count_unit": COUNT_API_INVOCATION_RETURN,
            "completion_coverage": COVERAGE_UNOBSERVED,
        }),
    }
}

/// Ident row → observation: a first-seen marker (`Discovered`, no verdict).
/// Call/class/symbol derive from the in-record head (no map join); the
/// status echoes the head class for Rust consumers (the wire renders
/// `not_applicable` for pre-return phases either way).
pub(crate) fn observation_for_ident(kctl: &KCtl, id: ObservationId) -> NativeObservation {
    let (fam, op, res, ctx) = unpack_head(kctl.val0);
    let (alg_len, drv_len) = kctl_unpack_lens(kctl.val1);
    let (call_kind, _) = op_call_phase(op, res);
    let ident_kind = match kctl.kind {
        KCTL_IDENT => "ident",
        KCTL_OVERFLOW => "overflow",
        _ => "unknown",
    };
    NativeObservation {
        id,
        backend: BackendId::KCrypto,
        target: None,
        object: None,
        implementation: None,
        phase: EvidencePhase::Discovered,
        call_kind,
        operation_class: class_for_op(op),
        native_name: symbol_for(fam, op).and_then(SafeTextId::new),
        native_code: None,
        native_result: NativeResult::KCrypto {
            status: status_for_res(res),
        },
        started_ns: Some(kctl.val2),
        ended_ns: None,
        correlation: None,
        integrity: IntegrityRef::new(0),
        backend_payload: json!({
            "row": "ident",
            "ident_kind": ident_kind,
            "key_hash": kctl.key_hash,
            "family": family_name(fam),
            "op": op_name(op),
            "result": result_name(res),
            "context": context_name(ctx),
            "name_lens": {"alg": alg_len, "drv": drv_len},
            "first_seen_ns": kctl.val2,
            "capture_profile": CAPTURE_API_RETURNS,
        }),
    }
}

/// `comm`/`pcomm` decode: raw `[u8; 16]` from the kernel, lossy UTF-8,
/// trimmed at the first NUL (same shape as [`name_from_words`]).
fn comm_str(raw: &[u8; 16]) -> String {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// `first_errno` render rule (Task 2 review M-1): `KERR` may hold queued
/// (`-EINPROGRESS`/`-EBUSY`) or positive-ok returns — render ONLY when the
/// value is < 0 and neither queued code, else omit (`None`).
fn render_first_errno(first_errno: Option<i32>) -> Option<i32> {
    first_errno.filter(|e| *e < 0 && *e != -libc::EINPROGRESS && *e != -libc::EBUSY)
}

/// Who row → observation: a caller-identity marker (`Discovered`, no
/// verdict — status pins neutral 0, and the wire renders `not_applicable`
/// for pre-return phases either way, as with idents).
///
/// Payload keys are exactly the K5 brief's list: `key_hash` (the row's
/// `kh`, straight from the `KWHO` key — joins the agg `key_hash`),
/// identity (`tgid`/`tid`/`comm`/`uid`/`cgroup`), parent
/// (`ppid`/`pcomm`), `stack` (`{id, frames: [{ip, sym|null}]}`,
/// symbolized through a shared [`SymTable`](crate::kallsyms::SymTable)), tallies
/// (`calls`/`first_ns`/`last_ns`), crypto params
/// (`blocksize`/`ivsize`/`min_keysize`/`max_keysize`), `first_errno`.
///
/// Omit-when-unresolved (never zero-filled in output): parent keys drop
/// when `ppid` is 0 with an all-zero `pcomm` (the BPF writes
/// both-or-neither, gated on `parent_ok`); params keys drop when `params`
/// is `None` (the BPF inserts `KPARAMS` iff `params_ok`, so an absent row
/// is unresolved); `first_errno` follows [`render_first_errno`]. The
/// `stack` block is never gated (a negative `id` is the raw helper errno
/// with empty `frames`; unresolvable syms are `null`, raw `ip` kept).
pub fn observation_for_who(
    who: &WhoSnapshot,
    id: ObservationId,
    table: &SymTable,
) -> NativeObservation {
    let parent_resolved = who.val.ppid != 0 || who.val.pcomm != [0u8; 16];
    let mut payload = json!({
        "row": "who",
        "key_hash": who.key.kh,
        "tgid": who.key.tgid,
        "tid": who.val.tid,
        "comm": comm_str(&who.val.comm),
        "uid": who.val.uid,
        "cgroup": who.val.cgroup,
        "stack": {
            "id": who.val.stack,
            "frames": symbolize_with(&who.stack_ips, table).into_iter().map(|frame| {
                json!({"ip": frame.ip, "sym": frame.sym})
            }).collect::<Vec<_>>(),
        },
        "calls": who.val.calls,
        "first_ns": who.val.first_ns,
        "last_ns": who.val.last_ns,
        "capture_profile": CAPTURE_API_RETURNS,
    });
    if parent_resolved {
        payload["ppid"] = json!(who.val.ppid);
        payload["pcomm"] = json!(comm_str(&who.val.pcomm));
    }
    if let Some(params) = &who.params {
        payload["blocksize"] = json!(params.blocksize);
        payload["ivsize"] = json!(params.ivsize);
        payload["min_keysize"] = json!(params.min_keysize);
        payload["max_keysize"] = json!(params.max_keysize);
    }
    if let Some(errno) = render_first_errno(who.first_errno) {
        payload["first_errno"] = json!(errno);
    }
    NativeObservation {
        id,
        backend: BackendId::KCrypto,
        target: None,
        object: None,
        implementation: None,
        phase: EvidencePhase::Discovered,
        call_kind: CallKind::Unknown,
        operation_class: OperationClass::Unknown,
        native_name: None,
        native_code: None,
        native_result: NativeResult::KCrypto { status: 0 },
        started_ns: Some(who.val.first_ns),
        ended_ns: Some(who.val.last_ns),
        correlation: None,
        integrity: IntegrityRef::new(0),
        backend_payload: payload,
    }
}
