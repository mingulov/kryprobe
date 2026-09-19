// SPDX-License-Identifier: GPL-3.0-or-later
//! K2 Task 1: kcrypto snapshot rows + codec + ring drain.
//!
//! Unprivileged codec tests (constructors, `parse_snapshot_row`,
//! `raw_event_for_*` + `split_header` roundtrip, `shared_losses` ctor)
//! run everywhere. The two privileged tests (`compat_*`, `snapshot_*`)
//! are `#[ignore]`d lane-style tests that return early (honest skip)
//! when not root or when BTF is missing (`kcrypto_agg` idiom); they
//! bring up the K1 configured sensor, drive `alg_fixture` traffic, and
//! prove byte-exactness against fixture truth (P4) plus ring-drain
//! compatibility against the K1 direct-mmap twin.
//!
//! Privileged tests hold the suite lock (sensors are system-wide; the
//! lock makes sensor lifetimes disjoint) and run under the workspace
//! BPF-lane lock. Alg choices vs the K1 suites (`cbc(aes)`, `gcm(aes)`,
//! `sha256`, `ctr(aes)`): compat uses `ecb(aes)` (distinct); the
//! exactness test reuses `cbc(aes)`/`gcm(aes)` (the only sane AEAD on
//! this host is `gcm(aes)`) with `sha512` for hash. Cross-binary alg
//! reuse is safe: privileged runs are lane-exclusive (lease
//! `leases/k2-lane.json`), each test owns a fresh sensor, and rows
//! match by decoded identity.

use kryprobe_abi::kcrypto_agg::{
    KCTL_IDENT, KCTL_OVERFLOW, KCtl, KFAM_AEAD, KFAM_AHASH, KFAM_ANY, KFAM_SHASH, KFAM_SK,
    KIDN_DROPS, KOP_ALLOC, KOP_DEC, KOP_DIGEST, KOP_ENC, KOP_FINUP, KRES_ERR, KRES_OK, VAgg,
    fold_vagg, kagg_from_bytes, kcrypto_ident_hash, kctl_from_bytes, kctl_pack_head,
    kctl_pack_lens, vagg_from_bytes,
};
use kryprobe_abi::{ABI_VERSION, BACKEND_KCRYPTO, EVENT_OBSERVATION, split_header};
use kryprobe_core::backend::RawEvent;
use kryprobe_core::error::BackendError;
use kryprobe_core::evidence::SharedLosses;
use kryprobe_privilege::btf_resolve::{ConfiguredKcrypto, load_kcrypto_configured};
use kryprobe_privilege::kcrypto_snapshot::{
    IDENT_BYTES_LEN, IdentBytes, ParsedRow, ROW_BYTES_LEN, ROW_KIND_AGG, ROW_KIND_IDENT,
    ROW_KIND_TOTALS, RowBytes, SNAPSHOT_VERSION, SnapshotRows, TOTALS_BYTES_LEN, TotalsBytes,
    parse_snapshot_row, raw_event_for_agg, raw_event_for_ident, raw_event_for_totals,
    shared_losses_from_snapshot, snapshot_rows,
};
use kryprobe_privilege::mapops::{map_lookup_bytes, possible_cpus};
use kryprobe_testkit::alg_fixture;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Pinned D7 surface (literals pin the snapshot contract; the module consts
// must equal them — a drift fails here, loudly).
// ---------------------------------------------------------------------------

#[test]
fn snapshot_consts_match_pinned_values() {
    assert_eq!(SNAPSHOT_VERSION, 0x01, "snapshot version pins 0x01");
    assert_eq!(ROW_KIND_AGG, 1, "agg kind pins 1");
    assert_eq!(ROW_KIND_TOTALS, 2, "totals kind pins 2");
    assert_eq!(ROW_KIND_IDENT, 3, "ident kind pins 3");
    assert_eq!(ROW_BYTES_LEN, 382, "agg row pins 382B (2 + 260 + 120)");
    assert_eq!(TOTALS_BYTES_LEN, 122, "totals row pins 122B (2 + 120)");
    assert_eq!(IDENT_BYTES_LEN, 50, "ident row pins 50B (2 + 48)");
}

// ---------------------------------------------------------------------------
// Hand-built payloads (valid 382/122/50).
// ---------------------------------------------------------------------------

/// Hand-encoded `VAgg` (little-endian field order per the struct decl).
fn vagg_bytes() -> [u8; 120] {
    let mut out = [0u8; 120];
    let words: [u64; 15] = [
        7, 224, 6, 1, 0, // calls, bytes, ok, errors, queued
        100, 200, // first_ns, last_ns
        1, 2, 3, 4, 0, 0, 0, 0, // lat[8]
    ];
    for (i, w) in words.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// Hand-encoded `KAgg` head + `cbc(aes)` name words + zero driver.
fn kagg_bytes() -> [u8; 260] {
    let mut out = [0u8; 260];
    out[0..4].copy_from_slice(&[KFAM_SK, KOP_ENC, KRES_OK, 0]);
    out[4..13].copy_from_slice(b"cbc(aes)\0");
    out
}

/// Valid 382B agg payload: ver + kind + `KAgg` + `VAgg`.
fn agg_payload() -> Vec<u8> {
    let mut out = Vec::with_capacity(382);
    out.push(0x01);
    out.push(1);
    out.extend_from_slice(&kagg_bytes());
    out.extend_from_slice(&vagg_bytes());
    out
}

/// Valid 122B totals payload: ver + kind + `VAgg`.
fn totals_payload() -> Vec<u8> {
    let mut out = Vec::with_capacity(122);
    out.push(0x01);
    out.push(2);
    out.extend_from_slice(&vagg_bytes());
    out
}

/// Valid 50B ident payload: ver + kind + `KCtl`.
fn ident_payload() -> Vec<u8> {
    let mut out = Vec::with_capacity(50);
    out.push(0x01);
    out.push(3);
    out.push(KCTL_IDENT);
    out.extend_from_slice(&[0u8; 7]); // _p[3] + alignment pad to key_hash@8
    out.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes()); // key_hash
    out.extend_from_slice(&kctl_pack_head(KFAM_SK, KOP_ENC, KRES_OK, 0).to_le_bytes());
    out.extend_from_slice(&kctl_pack_lens(8, 0).to_le_bytes());
    out.extend_from_slice(&12345u64.to_le_bytes()); // val2: first-seen ns
    out.extend_from_slice(&0u64.to_le_bytes()); // val3: reserved
    out
}

fn corrupt_reason(err: &BackendError) -> (&'static str, &Option<String>) {
    match err {
        BackendError::CorruptInput(reason) => (reason.reason, &reason.detail),
        other => panic!("expected CorruptInput, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Typed constructors: exact lengths accept, off-by-one rejects.
// ---------------------------------------------------------------------------

#[test]
fn typed_ctors_accept_exact_lengths() {
    assert_eq!(agg_payload().len(), 382);
    assert_eq!(totals_payload().len(), 122);
    assert_eq!(ident_payload().len(), 50);
    let row = RowBytes::new(agg_payload()).expect("382B row accepts");
    assert_eq!(row.0.len(), 382);
    let totals = TotalsBytes::new(totals_payload()).expect("122B totals accepts");
    assert_eq!(totals.0.len(), 122);
    let ident = IdentBytes::new(ident_payload()).expect("50B ident accepts");
    assert_eq!(ident.0.len(), 50);
}

#[test]
fn typed_ctors_reject_off_by_one_with_pinned_reasons() {
    for len in [0, 1, 381, 383, 500] {
        let err = RowBytes::new(vec![0u8; len]).expect_err("row ctor must reject");
        let (reason, detail) = corrupt_reason(&err);
        assert_eq!(reason, "snapshot_row_len", "row len {len}");
        assert_eq!(detail, &None, "no detail on row len");
    }
    for len in [0, 1, 121, 123, 382] {
        let err = TotalsBytes::new(vec![0u8; len]).expect_err("totals ctor must reject");
        let (reason, detail) = corrupt_reason(&err);
        assert_eq!(reason, "snapshot_totals_len", "totals len {len}");
        assert_eq!(detail, &None, "no detail on totals len");
    }
    for len in [0, 1, 49, 51, 122] {
        let err = IdentBytes::new(vec![0u8; len]).expect_err("ident ctor must reject");
        let (reason, detail) = corrupt_reason(&err);
        assert_eq!(reason, "snapshot_ident_len", "ident len {len}");
        assert_eq!(detail, &None, "no detail on ident len");
    }
}

// ---------------------------------------------------------------------------
// `parse_snapshot_row`: valid accepts, ver/kind/len reject pinned.
// ---------------------------------------------------------------------------

#[test]
fn parse_accepts_hand_built_rows() {
    match parse_snapshot_row(&agg_payload()).expect("valid agg parses") {
        ParsedRow::Agg { kagg, vagg } => {
            assert_eq!(
                (kagg.fam(), kagg.op(), kagg.res(), kagg.ctx()),
                (KFAM_SK, KOP_ENC, KRES_OK, 0)
            );
            assert_eq!(
                vagg,
                vagg_from_bytes(&vagg_bytes()).expect("hand VAgg decodes")
            );
            assert_eq!(vagg.calls, 7);
            assert_eq!(vagg.last_ns, 200);
        }
        ParsedRow::Totals { .. } => panic!("agg payload decoded as Totals"),
        ParsedRow::Ident { .. } => panic!("agg payload decoded as Ident"),
    }
    match parse_snapshot_row(&totals_payload()).expect("valid totals parses") {
        ParsedRow::Totals { vagg } => {
            assert_eq!(vagg.calls, 7);
            assert_eq!(vagg.first_ns, 100);
            assert_eq!(vagg.lat, [1, 2, 3, 4, 0, 0, 0, 0]);
        }
        ParsedRow::Agg { .. } => panic!("totals payload decoded as Agg"),
        ParsedRow::Ident { .. } => panic!("totals payload decoded as Ident"),
    }
    match parse_snapshot_row(&ident_payload()).expect("valid ident parses") {
        ParsedRow::Ident { kctl } => {
            assert_eq!(kctl.kind, KCTL_IDENT);
            assert_eq!(kctl.key_hash, 0x1122_3344_5566_7788);
            assert_eq!(kctl.val2, 12345);
            assert_eq!(kctl.val3, 0);
        }
        ParsedRow::Agg { .. } => panic!("ident payload decoded as Agg"),
        ParsedRow::Totals { .. } => panic!("ident payload decoded as Totals"),
    }
}

#[test]
fn parse_rejects_bad_version_with_pinned_reason() {
    // Empty payload has no version to verify: version error, not a panic.
    let (reason, _) = corrupt_reason(&parse_snapshot_row(&[]).expect_err("empty rejects"));
    assert_eq!(reason, "snapshot_version");
    for ver in [0x00, 0x02, 0xff] {
        let mut bad = agg_payload();
        bad[0] = ver;
        let err = parse_snapshot_row(&bad).expect_err("bad ver rejects");
        let (reason, detail) = corrupt_reason(&err);
        assert_eq!(reason, "snapshot_version", "ver {ver:#x}");
        assert_eq!(detail, &None);
    }
}

#[test]
fn parse_rejects_bad_kind_with_pinned_reason() {
    // One-byte payload has no kind: kind error, not a panic.
    let (reason, _) = corrupt_reason(&parse_snapshot_row(&[0x01]).expect_err("1B rejects"));
    assert_eq!(reason, "snapshot_kind");
    for kind in [0, 4, 5, 255] {
        let mut bad = agg_payload();
        bad[1] = kind;
        let err = parse_snapshot_row(&bad).expect_err("bad kind rejects");
        let (reason, detail) = corrupt_reason(&err);
        assert_eq!(reason, "snapshot_kind", "kind {kind}");
        assert_eq!(detail, &None);
    }
}

#[test]
fn parse_rejects_bad_length_with_pinned_reasons() {
    // Kind-valid but short/long: per-kind length reasons.
    let mut short = agg_payload();
    short.pop();
    let (reason, _) = corrupt_reason(&parse_snapshot_row(&short).expect_err("381B agg rejects"));
    assert_eq!(reason, "snapshot_row_len");
    let mut long = agg_payload();
    long.push(0);
    let (reason, _) = corrupt_reason(&parse_snapshot_row(&long).expect_err("383B agg rejects"));
    assert_eq!(reason, "snapshot_row_len");
    let mut short = totals_payload();
    short.truncate(100);
    let (reason, _) = corrupt_reason(&parse_snapshot_row(&short).expect_err("100B totals rejects"));
    assert_eq!(reason, "snapshot_totals_len");
    let mut long = totals_payload();
    long.extend_from_slice(&[0u8; 300]);
    let (reason, _) = corrupt_reason(&parse_snapshot_row(&long).expect_err("long totals rejects"));
    assert_eq!(reason, "snapshot_totals_len");
    let mut short = ident_payload();
    short.truncate(49);
    let (reason, _) = corrupt_reason(&parse_snapshot_row(&short).expect_err("49B ident rejects"));
    assert_eq!(reason, "snapshot_ident_len");
    // Check order is ver -> kind -> len: a payload wrong in every way
    // reports the version first.
    let err = parse_snapshot_row(&[0x00, 0xff, 0x00]).expect_err("triple-wrong rejects");
    assert_eq!(corrupt_reason(&err).0, "snapshot_version");
    let err = parse_snapshot_row(&[0x01, 0xff, 0x00]).expect_err("kind+len-wrong rejects");
    assert_eq!(corrupt_reason(&err).0, "snapshot_kind");
}

// ---------------------------------------------------------------------------
// `raw_event_for_*`: headers per D7 pass `split_header`.
// ---------------------------------------------------------------------------

/// 8-aligned scratch: `split_header` requires an 8-aligned buffer
/// (testkit `roundtrip.rs` idiom).
#[repr(C, align(8))]
struct Scratch([u8; 512]);

/// Serialize one [`RawEvent`] header (little-endian `repr(C)` field
/// order) + payload into aligned scratch, then `split_header` must
/// accept it and return the same payload bytes.
fn assert_header_roundtrips(event: &RawEvent<'_>, payload: &[u8], what: &str) {
    assert_eq!(
        std::mem::size_of::<kryprobe_abi::RawEventHeader>(),
        56,
        "header pins 56B"
    );
    let total = 56 + payload.len();
    let mut scratch = Scratch([0u8; 512]);
    let h = &event.header;
    scratch.0[0..2].copy_from_slice(&h.abi_version.to_le_bytes());
    scratch.0[2..4].copy_from_slice(&h.backend_id.to_le_bytes());
    scratch.0[4..6].copy_from_slice(&h.event_kind.to_le_bytes());
    scratch.0[6..8].copy_from_slice(&h.flags.to_le_bytes());
    scratch.0[8..12].copy_from_slice(&h.total_len.to_le_bytes());
    scratch.0[12..16].copy_from_slice(&h.cpu.to_le_bytes());
    scratch.0[16..24].copy_from_slice(&h.session_cookie.to_le_bytes());
    scratch.0[24..32].copy_from_slice(&h.monotonic_ns.to_le_bytes());
    scratch.0[32..36].copy_from_slice(&h.tgid.to_le_bytes());
    scratch.0[36..40].copy_from_slice(&h.tid.to_le_bytes());
    scratch.0[40..48].copy_from_slice(&h.process_generation.to_le_bytes());
    scratch.0[48..52].copy_from_slice(&h.plan_generation.to_le_bytes());
    scratch.0[52..56].copy_from_slice(&h.reserved.to_le_bytes());
    scratch.0[56..total].copy_from_slice(payload);
    let (split, body) = split_header(&scratch.0[..total]).expect("D7 header splits");
    assert_eq!(body, payload, "{what}: split payload roundtrips");
    assert_eq!(split, &event.header, "{what}: split header roundtrips");
}

fn assert_d7_header(event: &RawEvent<'_>, payload_len: usize, monotonic_ns: u64, what: &str) {
    let h = &event.header;
    assert_eq!(h.abi_version, ABI_VERSION, "{what}: abi version");
    assert_eq!(h.backend_id, BACKEND_KCRYPTO, "{what}: backend id pins 3");
    assert_eq!(h.backend_id, 3, "{what}: backend id literal");
    assert_eq!(h.event_kind, EVENT_OBSERVATION, "{what}: event kind");
    assert_eq!(h.flags & 1, 1, "{what}: flags bit0 status_canonical");
    assert_eq!(h.flags, 1, "{what}: flags pins exactly bit0");
    assert_eq!(
        h.total_len,
        (56 + payload_len) as u32,
        "{what}: total_len covers header + payload"
    );
    // System-wide aggregates have no single tgid/tid/cpu: zeros are
    // documented-unknown per C10, never fabricated attribution.
    assert_eq!(h.tgid, 0, "{what}: tgid unknown-zero");
    assert_eq!(h.tid, 0, "{what}: tid unknown-zero");
    assert_eq!(h.cpu, 0, "{what}: cpu unknown-zero");
    assert_eq!(h.session_cookie, 0, "{what}: session cookie zero");
    assert_eq!(h.process_generation, 0, "{what}: process generation zero");
    assert_eq!(h.plan_generation, 0, "{what}: plan generation zero");
    assert_eq!(h.reserved, 0, "{what}: reserved zero");
    assert_eq!(
        h.monotonic_ns, monotonic_ns,
        "{what}: monotonic_ns from row"
    );
}

#[test]
fn raw_event_headers_pass_split_header() {
    let row = RowBytes::new(agg_payload()).expect("row");
    let event = raw_event_for_agg(&row);
    assert_eq!(event.payload, &row.0[..], "agg payload borrows the row");
    assert!(
        std::ptr::eq(event.payload.as_ptr(), row.0.as_ptr()),
        "agg payload is a borrow, not a copy"
    );
    assert_d7_header(&event, 382, 200, "agg");
    assert_header_roundtrips(&event, &row.0, "agg");

    let totals = TotalsBytes::new(totals_payload()).expect("totals");
    let event = raw_event_for_totals(&totals);
    assert!(
        std::ptr::eq(event.payload.as_ptr(), totals.0.as_ptr()),
        "totals payload is a borrow, not a copy"
    );
    assert_d7_header(&event, 122, 200, "totals");
    assert_header_roundtrips(&event, &totals.0, "totals");

    let ident = IdentBytes::new(ident_payload()).expect("ident");
    let event = raw_event_for_ident(&ident);
    assert!(
        std::ptr::eq(event.payload.as_ptr(), ident.0.as_ptr()),
        "ident payload is a borrow, not a copy"
    );
    assert_d7_header(&event, 50, 12345, "ident");
    assert_header_roundtrips(&event, &ident.0, "ident");
}

// ---------------------------------------------------------------------------
// `shared_losses_from_snapshot`: ring drops ride through, queue pins 0.
// ---------------------------------------------------------------------------

#[test]
fn shared_losses_ctor_wires_ring_drops_with_zero_queue() {
    let snap = SnapshotRows {
        rows: vec![RowBytes::new(agg_payload()).expect("row")],
        totals: Some(TotalsBytes::new(totals_payload()).expect("totals")),
        idents: vec![IdentBytes::new(ident_payload()).expect("ident")],
        overflow_identities: 0,
        monotonic_ns: 999,
    };
    for drops in [0u8, 1, 255] {
        assert_eq!(
            shared_losses_from_snapshot(&snap, drops),
            SharedLosses::new(u64::from(drops), 0),
            "drops={drops}: ring rides, queue pins 0 (v0.1 short-lived drain)"
        );
    }
}

// ---------------------------------------------------------------------------
// Privileged scaffolding (lane_ready + suite lock + sensor: kcrypto_agg/canary
// idiom; the ring twin below is a port of the K1 direct-mmap walk).
// ---------------------------------------------------------------------------

/// Workspace-relative path of the built kcrypto object.
fn kcrypto_object_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("kryprobe-bpf")
        .join("kcrypto.bpf.o")
}

fn kcrypto_bytes() -> Vec<u8> {
    let path = kcrypto_object_path();
    assert!(
        path.is_file(),
        "missing BPF kcrypto object at {} — run `cargo xtask build --bpf`",
        path.display()
    );
    std::fs::read(&path).expect("test fixture must be readable")
}

fn is_root() -> bool {
    // SAFETY: idempotent getter.
    unsafe { libc::geteuid() == 0 }
}

fn btf_available() -> bool {
    std::fs::metadata("/sys/kernel/btf/vmlinux").is_ok()
}

/// Privileged-gate: true when this test must run (root + BTF).
/// Callers `return` early on false (honest skip, prints why).
fn lane_ready(name: &str) -> bool {
    if !is_root() {
        println!("SKIP: {name} requires root (euid != 0)");
        return false;
    }
    if !btf_available() {
        println!("SKIP: {name} requires /sys/kernel/btf/vmlinux");
        return false;
    }
    true
}

/// Suite serialization lock: the sensors are system-wide, so parallel
/// privileged tests would race each other's dumps. Each privileged test
/// holds this across its whole body (attach→detach), making sensor
/// lifetimes disjoint (`kcrypto_agg` idiom). Poison-tolerant.
static SUITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn suite_guard() -> std::sync::MutexGuard<'static, ()> {
    SUITE_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn words_to_bytes(words: &[u64; 16]) -> [u8; 128] {
    let mut out = [0u8; 128];
    for (i, w) in words.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Twin ring peek: the K1 direct-mmap consumer walk (port of the
/// `kcrypto_agg::drain_ring` oracle: same mmap pair, same framing math,
/// same `kctl_from_bytes` decode), read-only — the consumer position is
/// left alone so the snapshotter's own drain runs after on identical
/// bytes. Test-only compat oracle, never shipped.
fn twin_peek_ring(sensor: &ConfiguredKcrypto) -> Vec<Vec<u8>> {
    let page = 4096usize;
    let max = 1usize << 20;
    // SAFETY: page-aligned lengths, valid map fd, checked for failure.
    let cons = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            sensor.loaded.maps.ring.as_raw_fd(),
            0,
        )
    };
    assert!(cons != libc::MAP_FAILED, "ring consumer mmap");
    struct Unmap {
        ptr: *mut libc::c_void,
        len: usize,
    }
    impl Drop for Unmap {
        fn drop(&mut self) {
            unsafe { libc::munmap(self.ptr, self.len) };
        }
    }
    let _cons = Unmap {
        ptr: cons,
        len: page,
    };
    let prod_len = page + 2 * max;
    // SAFETY: same contract as above.
    let prod = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            prod_len,
            libc::PROT_READ,
            libc::MAP_SHARED,
            sensor.loaded.maps.ring.as_raw_fd(),
            page as libc::off_t,
        )
    };
    assert!(prod != libc::MAP_FAILED, "ring producer mmap");
    let _prod = Unmap {
        ptr: prod,
        len: prod_len,
    };
    // SAFETY: the two header words are live for the mappings' lifetime.
    let consumer = unsafe { *(cons as *const u64) };
    let producer = unsafe { *(prod as *const u64) };
    // SAFETY: the double mapping spans `2 * max` readable bytes.
    let data = unsafe { std::slice::from_raw_parts((prod as *const u8).add(page), 2 * max) };
    let mask = max as u64 - 1;
    let mut out = Vec::new();
    let mut pos = consumer;
    let mut visited = 0;
    while pos < producer && visited < 1024 {
        visited += 1;
        let off = (pos & mask) as usize;
        let hdr = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        if hdr & (1 << 31) != 0 {
            break; // Busy (writer in flight): stop like the drain worker.
        }
        let len = (hdr & !(1 << 31 | 1 << 30)) as usize;
        if len > max {
            break; // Corrupt length: stop, never over-read.
        }
        let total = 8 + ((len + 7) & !7);
        if pos.saturating_add(total as u64) > producer {
            break; // Torn record: stop.
        }
        if hdr & (1 << 30) == 0 {
            out.push(data[off + 8..off + 8 + len].to_vec());
        }
        pos = pos.saturating_add(total as u64);
    }
    out
}

/// Read the `KIDN[KIDN_DROPS]` ring-reserve counter via raw map ops (0
/// when the key is absent — the `kcrypto_agg::dump_kidn` idiom). The
/// independent oracle for the drops wiring (the snapshotter reads the
/// same key internally).
fn twin_read_drops(sensor: &ConfiguredKcrypto) -> u8 {
    map_lookup_bytes(
        &sensor.loaded.maps.ident,
        &KIDN_DROPS.to_le_bytes(),
        1,
        "snapshot-twin/kidn-drops",
    )
    .map(|v| v[0])
    .unwrap_or(0)
}

/// One decoded snapshot agg row (attribution + names + folded value).
struct SnapRow {
    fam: u8,
    op: u8,
    res: u8,
    ctx: u8,
    alg: String,
    drv: String,
    alg_words: [u64; 16],
    drv_words: [u64; 16],
    val: VAgg,
}

/// Decode every snapshot agg row via the fallible entry (the same
/// `parse_snapshot_row` Task 2's backend calls — the test exercises the
/// shipped decode path, not the raw ABI mirrors).
fn decode_snapshot_rows(snap: &SnapshotRows) -> Vec<SnapRow> {
    snap.rows
        .iter()
        .map(
            |row| match parse_snapshot_row(&row.0).expect("snapshot row parses") {
                ParsedRow::Agg { kagg, vagg } => {
                    let alg_words = kagg.alg();
                    let drv_words = kagg.drv();
                    SnapRow {
                        fam: kagg.fam(),
                        op: kagg.op(),
                        res: kagg.res(),
                        ctx: kagg.ctx(),
                        alg: cstr(&words_to_bytes(&alg_words)),
                        drv: cstr(&words_to_bytes(&drv_words)),
                        alg_words,
                        drv_words,
                        val: vagg,
                    }
                }
                ParsedRow::Totals { .. } => panic!("snapshot agg row decoded as Totals"),
                ParsedRow::Ident { .. } => panic!("snapshot agg row decoded as Ident"),
            },
        )
        .collect()
}

/// Decode the snapshot totals row via the fallible entry.
fn decode_snapshot_totals(snap: &SnapshotRows) -> VAgg {
    let totals = snap.totals.as_ref().expect("KTOT row present");
    match parse_snapshot_row(&totals.0).expect("totals row parses") {
        ParsedRow::Totals { vagg } => vagg,
        ParsedRow::Agg { .. } => panic!("snapshot totals row decoded as Agg"),
        ParsedRow::Ident { .. } => panic!("snapshot totals row decoded as Ident"),
    }
}

/// Decode every snapshot ident via the fallible entry.
fn decode_snapshot_idents(snap: &SnapshotRows) -> Vec<KCtl> {
    snap.idents
        .iter()
        .map(
            |ident| match parse_snapshot_row(&ident.0).expect("ident parses") {
                ParsedRow::Ident { kctl } => kctl,
                ParsedRow::Agg { .. } => panic!("snapshot ident decoded as Agg"),
                ParsedRow::Totals { .. } => panic!("snapshot ident decoded as Totals"),
            },
        )
        .collect()
}

/// Sum rows matching `(fam, op, res, alg)` over all contexts (the P4
/// find/sum: background + cross-test traffic lives in other rows).
fn sum_rows(rows: &[SnapRow], fam: u8, op: u8, res: u8, alg: &str) -> VAgg {
    let mut out = VAgg::default();
    for row in rows
        .iter()
        .filter(|r| r.fam == fam && r.op == op && r.res == res && r.alg == alg)
    {
        out.calls = out.calls.saturating_add(row.val.calls);
        out.bytes = out.bytes.saturating_add(row.val.bytes);
        out.ok = out.ok.saturating_add(row.val.ok);
        out.errors = out.errors.saturating_add(row.val.errors);
        out.queued = out.queued.saturating_add(row.val.queued);
    }
    out
}

#[test]
#[ignore = "BPF lane: run under sudo with the lane lock"]
fn compat_ring_matches_canary_twin() {
    let _guard = suite_guard();
    if !lane_ready("compat_ring_matches_canary_twin") {
        return;
    }
    let bytes = kcrypto_bytes();
    let (sensor, _points) = load_kcrypto_configured(&bytes, None)
        .unwrap_or_else(|err| panic!("configured bring-up failed: {err}"));
    let counts = alg_fixture::skcipher_roundtrip("ecb(aes)", 5).expect("compat traffic");
    assert_eq!((counts.enc, counts.dec), (5, 5));
    // Twin first (read-only peek): the snapshotter drains after on the
    // identical pending bytes.
    let twin = twin_peek_ring(&sensor);
    assert!(!twin.is_empty(), "ring must carry compat IDENTs");
    for rec in &twin {
        assert_eq!(rec.len(), 48, "kcrypto ring records are 48B KCtl");
        kctl_from_bytes(rec).expect("twin record parses as KCtl");
    }
    let snap = snapshot_rows(&sensor).expect("snapshot_rows");
    // Zero delta: same records, same bytes, same order.
    assert_eq!(
        snap.idents.len(),
        twin.len(),
        "snapshot idents == twin records ({} vs {})",
        snap.idents.len(),
        twin.len()
    );
    for (ident, rec) in snap.idents.iter().zip(twin.iter()) {
        assert_eq!(&ident.0[2..], &rec[..], "ident body == twin record bytes");
    }
    // Overflow accounting agrees with the twin's kinds.
    let twin_overflow = twin
        .iter()
        .filter(|rec| kctl_from_bytes(rec).expect("KCtl").kind == KCTL_OVERFLOW)
        .count() as u64;
    assert_eq!(
        snap.overflow_identities, twin_overflow,
        "overflow count == twin OVERFLOW records"
    );
    assert_eq!(snap.overflow_identities, 0, "healthy drain has no OVERFLOW");
    // The snapshot consumed the ring: a post-drain peek is empty.
    assert!(
        twin_peek_ring(&sensor).is_empty(),
        "post-snapshot ring must be drained"
    );
    // Drops agree with the independent KIDN read (healthy: zero).
    let drops = twin_read_drops(&sensor);
    assert_eq!(drops, 0, "ring-reserve drops counter pins zero");
    assert_eq!(
        shared_losses_from_snapshot(&snap, drops),
        SharedLosses::new(0, 0),
        "healthy shared losses pin zero"
    );
}

#[test]
#[ignore = "BPF lane: run under sudo with the lane lock"]
fn snapshot_byte_exactness_against_fixture() {
    let _guard = suite_guard();
    if !lane_ready("snapshot_byte_exactness_against_fixture") {
        return;
    }
    let bytes = kcrypto_bytes();
    let (sensor, _points) = load_kcrypto_configured(&bytes, None)
        .unwrap_or_else(|err| panic!("configured bring-up failed: {err}"));
    // Committed fixture traffic, three families + the error path.
    let sk = alg_fixture::skcipher_roundtrip("cbc(aes)", 20).expect("skcipher traffic");
    assert_eq!((sk.enc, sk.dec), (20, 20));
    let single = alg_fixture::hash_digest("sha512", 8).expect("hash traffic");
    assert_eq!((single.digests, single.digest_len), (8, 64));
    let multi = alg_fixture::hash_digest_multi("sha512", 4).expect("hashmulti traffic");
    assert_eq!(multi.digests, 4);
    let aead = alg_fixture::aead_roundtrip("gcm(aes)", 10).expect("aead traffic");
    assert_eq!((aead.enc, aead.dec), (10, 10));
    alg_fixture::aead_decrypt_bad_tag("gcm(aes)").expect("bad-tag decrypt must EBADMSG");
    let snap = snapshot_rows(&sensor).expect("snapshot_rows");
    let rows = decode_snapshot_rows(&snap);
    assert!(!rows.is_empty(), "snapshot must carry agg rows");
    // P4 skcipher exactness (fixture truth vs sensor delta).
    let enc = sum_rows(&rows, KFAM_SK, KOP_ENC, KRES_OK, "cbc(aes)");
    assert_eq!(enc.calls, 20, "sk enc calls");
    assert_eq!(enc.bytes, 20 * 32, "sk enc bytes (cryptlen 32)");
    assert_eq!(enc.ok, 20, "sk enc ok");
    assert_eq!(enc.errors + enc.queued, 0, "sk enc clean buckets");
    let dec = sum_rows(&rows, KFAM_SK, KOP_DEC, KRES_OK, "cbc(aes)");
    assert_eq!(dec.calls, 20, "sk dec calls");
    assert_eq!(dec.bytes, 20 * 32, "sk dec bytes");
    assert_eq!(dec.ok, 20, "sk dec ok");
    let alloc = sum_rows(&rows, KFAM_ANY, KOP_ALLOC, KRES_OK, "cbc(aes)");
    assert_eq!(alloc.calls, 1, "sk alloc calls (one bind)");
    assert_eq!(alloc.bytes, 0, "alloc carries no bytes");
    // P4 hash exactness: one ahash + one shash observation per
    // single-shot op (each 64B), two finups per multi digest.
    let ahash = sum_rows(&rows, KFAM_AHASH, KOP_DIGEST, KRES_OK, "sha512");
    assert_eq!(ahash.calls, 8, "ahash digest calls");
    assert_eq!(ahash.bytes, 8 * 64, "ahash digest bytes");
    assert_eq!(ahash.ok, 8, "ahash digest ok");
    let shash = sum_rows(&rows, KFAM_SHASH, KOP_DIGEST, KRES_OK, "sha512");
    assert_eq!(shash.calls, 8, "shash digest calls");
    assert_eq!(shash.bytes, 8 * 64, "shash digest bytes");
    assert_eq!(shash.ok, 8, "shash digest ok");
    let finup = sum_rows(&rows, KFAM_SHASH, KOP_FINUP, KRES_OK, "sha512");
    assert_eq!(finup.calls, 8, "finup calls (2 per multi digest)");
    assert_eq!(finup.bytes, 4 * 32, "finup bytes conserved");
    assert_eq!(finup.ok, 8, "finup ok");
    // P4 AEAD exactness: N=10 clean + bad-tag setup enc + failed dec.
    let aenc = sum_rows(&rows, KFAM_AEAD, KOP_ENC, KRES_OK, "gcm(aes)");
    assert_eq!(aenc.calls, 11, "aead enc calls (10 + bad-tag setup)");
    assert_eq!(aenc.bytes, 11 * 32, "aead enc bytes");
    assert_eq!(aenc.ok, 11, "aead enc ok");
    let adec = sum_rows(&rows, KFAM_AEAD, KOP_DEC, KRES_OK, "gcm(aes)");
    assert_eq!(adec.calls, 10, "aead dec calls");
    assert_eq!(adec.bytes, 10 * 48, "aead dec bytes (cryptlen incl. tag)");
    assert_eq!(adec.ok, 10, "aead dec ok");
    let derr = sum_rows(&rows, KFAM_AEAD, KOP_DEC, KRES_ERR, "gcm(aes)");
    assert_eq!(derr.calls, 1, "bad-tag decrypt observed");
    assert_eq!(derr.errors, 1, "bad-tag decrypt classified errors");
    assert_eq!(derr.ok, 0, "bad-tag decrypt not ok");
    assert_eq!(derr.bytes, 48, "bad-tag decrypt bytes (failed leg sized)");
    // Conservation on every row; totals conservation KTOT == ΣKAGG.
    for row in &rows {
        assert_eq!(
            row.val.ok + row.val.errors + row.val.queued,
            row.val.calls,
            "row {} op={} breaks conservation",
            row.alg,
            row.op
        );
        assert_eq!(row.val.lat, [0; 8], "lat pins zero (C4)");
    }
    let tot = decode_snapshot_totals(&snap);
    let mut sum = VAgg::default();
    for row in &rows {
        sum.calls = sum.calls.saturating_add(row.val.calls);
        sum.bytes = sum.bytes.saturating_add(row.val.bytes);
        sum.ok = sum.ok.saturating_add(row.val.ok);
        sum.errors = sum.errors.saturating_add(row.val.errors);
        sum.queued = sum.queued.saturating_add(row.val.queued);
    }
    assert_eq!(tot.calls, sum.calls, "KTOT.calls == ΣKAGG");
    assert_eq!(tot.bytes, sum.bytes, "KTOT.bytes == ΣKAGG");
    assert_eq!(tot.ok, sum.ok, "KTOT.ok == ΣKAGG");
    assert_eq!(tot.errors, sum.errors, "KTOT.errors == ΣKAGG");
    assert_eq!(tot.queued, sum.queued, "KTOT.queued == ΣKAGG");
    // Ring idents match first-seen identities: every IDENT joins a
    // dumped row by hash with consistent head/lengths/window (C5).
    let idents = decode_snapshot_idents(&snap);
    assert!(!idents.is_empty(), "snapshot must carry IDENTs");
    for ctl in idents.iter().filter(|c| c.kind == KCTL_IDENT) {
        let gated: Vec<&SnapRow> = rows
            .iter()
            .filter(|r| kcrypto_ident_hash(r.fam, r.op, &r.alg_words, &r.drv_words) == ctl.key_hash)
            .collect();
        assert!(
            !gated.is_empty(),
            "IDENT {:016x} joins no snapshot row ({} rows)",
            ctl.key_hash,
            rows.len()
        );
        let heads: Vec<u64> = gated
            .iter()
            .map(|r| kctl_pack_head(r.fam, r.op, r.res, r.ctx))
            .collect();
        assert!(
            heads.contains(&ctl.val0),
            "IDENT head {:#x} matches no row of gate {:016x}",
            ctl.val0,
            ctl.key_hash
        );
        let (alg_len, drv_len) = (gated[0].alg.len() as u32, gated[0].drv.len() as u32);
        assert_eq!(
            ctl.val1,
            kctl_pack_lens(alg_len, drv_len),
            "IDENT lens mismatch for {:016x}",
            ctl.key_hash
        );
        let first = gated.iter().map(|r| r.val.first_ns).min().unwrap_or(0);
        let last = gated.iter().map(|r| r.val.last_ns).max().unwrap_or(0);
        assert!(
            first <= ctl.val2 && ctl.val2 <= last,
            "IDENT ns {} outside gate window [{first}, {last}]",
            ctl.val2
        );
        assert_eq!(ctl.val3, 0, "IDENT val3 must be reserved zero");
    }
    // Healthy drain: no OVERFLOW, drops zero, losses wired.
    assert_eq!(snap.overflow_identities, 0, "overflow_identities pins 0");
    assert!(
        idents.iter().all(|c| c.kind == KCTL_IDENT),
        "only IDENT kinds on a healthy ring"
    );
    let drops = twin_read_drops(&sensor);
    assert_eq!(drops, 0, "ring-reserve drops counter pins zero");
    assert_eq!(
        shared_losses_from_snapshot(&snap, drops),
        SharedLosses::new(0, 0),
        "healthy shared losses pin zero"
    );
    // Snapshot wall: a live CLOCK_MONOTONIC stamp, not fabricable from rows.
    assert!(snap.monotonic_ns > 0, "snapshot wall must be nonzero");
    let now = monotonic_now();
    assert!(
        snap.monotonic_ns <= now,
        "snapshot wall {} must not exceed the post-snapshot clock {now}",
        snap.monotonic_ns
    );
    // Independent oracle cross-check: the same `fold_vagg` the K1 suite
    // calls, over raw percpu lanes read straight from the maps, equals
    // the snapshot's decoded rows (guards the snapshotter's fold path).
    assert_snapshot_fold_matches_raw_maps(&sensor, &rows, &tot);
}

/// CLOCK_MONOTONIC now (test-side wall oracle).
fn monotonic_now() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid out-pointer; CLOCK_MONOTONIC always supported.
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    assert_eq!(ret, 0, "clock_gettime must succeed");
    (ts.tv_sec.max(0) as u64) * 1_000_000_000 + (ts.tv_nsec.max(0) as u64)
}

/// Oracle fold: raw percpu lanes straight from KAGG/KTOT (independent
/// map reads, same `fold_vagg`/decoders as K1) must equal the
/// snapshot-decoded rows. Catches fold/encode drift in the snapshotter.
fn assert_snapshot_fold_matches_raw_maps(sensor: &ConfiguredKcrypto, rows: &[SnapRow], tot: &VAgg) {
    use kryprobe_privilege::mapops::map_get_next_key;
    let ncpu = possible_cpus() as usize;
    let mut key: Option<Vec<u8>> = None;
    let mut raw_rows = 0;
    loop {
        let next = map_get_next_key(
            &sensor.loaded.maps.agg,
            key.as_deref(),
            260,
            "snapshot-twin/kagg-iter",
        )
        .expect("KAGG iteration");
        let Some(k) = next else { break };
        let raw = map_lookup_bytes(
            &sensor.loaded.maps.agg,
            &k,
            120 * ncpu,
            "snapshot-twin/kagg-val",
        )
        .expect("KAGG lookup");
        let mut lanes = Vec::with_capacity(ncpu);
        for c in 0..ncpu {
            lanes.push(vagg_from_bytes(&raw[c * 120..(c + 1) * 120]).expect("VAgg lane"));
        }
        let folded = fold_vagg(&lanes);
        let keyd = kagg_from_bytes(&k).expect("KAgg key");
        let alg = cstr(&words_to_bytes(&keyd.alg()));
        // Match on (fam, op, res, alg, drv): res distinguishes rows the
        // identity hash gates together.
        let found = rows.iter().find(|r| {
            r.fam == keyd.fam()
                && r.op == keyd.op()
                && r.res == keyd.res()
                && r.ctx == keyd.ctx()
                && r.alg_words == keyd.alg()
                && r.drv_words == keyd.drv()
        });
        let found = found.unwrap_or_else(|| {
            panic!(
                "oracle row fam={} op={} res={} alg={alg:?} missing from snapshot",
                keyd.fam(),
                keyd.op(),
                keyd.res()
            )
        });
        assert_eq!(
            found.val.calls,
            folded.calls,
            "fold calls match for {alg:?} op={}",
            keyd.op()
        );
        assert_eq!(found.val.bytes, folded.bytes, "fold bytes match");
        assert_eq!(found.val.ok, folded.ok, "fold ok match");
        assert_eq!(found.val.errors, folded.errors, "fold errors match");
        assert_eq!(found.val.queued, folded.queued, "fold queued match");
        assert_eq!(found.val.first_ns, folded.first_ns, "fold first_ns match");
        assert_eq!(found.val.last_ns, folded.last_ns, "fold last_ns match");
        assert_eq!(found.val.lat, folded.lat, "fold lat match");
        raw_rows += 1;
        key = Some(k);
    }
    assert_eq!(raw_rows, rows.len(), "oracle sees every snapshot row");
    let raw = map_lookup_bytes(
        &sensor.loaded.maps.total,
        &0u32.to_le_bytes(),
        120 * ncpu,
        "snapshot-twin/ktot",
    )
    .expect("KTOT lookup");
    let mut lanes = Vec::with_capacity(ncpu);
    for c in 0..ncpu {
        lanes.push(vagg_from_bytes(&raw[c * 120..(c + 1) * 120]).expect("KTOT lane"));
    }
    assert_eq!(
        fold_vagg(&lanes),
        *tot,
        "oracle KTOT fold == snapshot totals"
    );
}
