// SPDX-License-Identifier: GPL-3.0-or-later
//! K1 Task 3: configured-entry proof + secret-canary tripwire.
//!
//! `kconfig_bytes_match_live_resolver` is the unprivileged half of
//! brief Step 1 (resolve + KCFG bytes equal the 9 resolved offsets +
//! pad per C2, from live BTF). `configured_entry_writes_kcfg_from_
//! resolver` is the privileged half: `load_kcrypto_configured` writes
//! the 44B KCFG row the live resolver dictates, attaches all 9 points,
//! and the row reads back byte-identical (from the map fd, then again
//! after a real bpffs pin). `canary_kcrypto` plants `KPROBE-CANARY-*`
//! markers in key, IV, and plaintext fixture buffers and byte-scans
//! every `KAGG`/`KTOT`/`KIDN`/`KRING`/`KCFG` dump for zero occurrences
//! (kp2 §9 never-list tripwire: any drift that leaks buffer bytes
//! fails the build).
//!
//! Honest skips: the privileged tests are `#[ignore]`d lane tests
//! (`cargo xtask test bpf`) and return early when not root or when BTF
//! is missing (`kcrypto_agg` idiom). No suite mutex: neither test
//! asserts totals, and the canary matches rows by identity, so the two
//! sensors cannot race each other's assertions.

use kryprobe_abi::kcrypto_agg::{
    KFAM_SK, KOP_DEC, KOP_ENC, KRES_OK, VAgg, fold_vagg, kagg_from_bytes, vagg_from_bytes,
};
use kryprobe_privilege::bpfloader::{PointStatus, pin_fd};
use kryprobe_privilege::btf_resolve::{
    AttachOutcome, ConfiguredKcrypto, kconfig_from_offsets, load_kcrypto_configured,
    resolve_offsets,
};
use kryprobe_privilege::mapops::{map_get_next_key, map_lookup_bytes, possible_cpus};
use kryprobe_testkit::alg_fixture;
use std::path::PathBuf;

/// Byte-scan needle: every canary fixture buffer starts with this.
const NEEDLE: &[u8] = b"KPROBE-CANARY";

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

/// One decoded `KAGG` row (positive-control shape: attribution + name).
struct Row {
    fam: u8,
    op: u8,
    res: u8,
    alg: String,
    val: VAgg,
}

/// Decode every `KAGG` row (key iteration + per-CPU fold).
fn dump_kagg_rows(sensor: &ConfiguredKcrypto) -> Vec<Row> {
    let ncpu = possible_cpus() as usize;
    let mut rows = Vec::new();
    let mut key: Option<Vec<u8>> = None;
    loop {
        let next = map_get_next_key(
            &sensor.loaded.maps.agg,
            key.as_deref(),
            260,
            "canary/kagg-iter",
        )
        .expect("KAGG iteration");
        let Some(k) = next else { break };
        assert_eq!(k.len(), 260, "KAGG key size drifted");
        let raw = map_lookup_bytes(&sensor.loaded.maps.agg, &k, 120 * ncpu, "canary/kagg-val")
            .expect("KAGG lookup");
        let mut lanes = Vec::with_capacity(ncpu);
        for c in 0..ncpu {
            lanes.push(vagg_from_bytes(&raw[c * 120..(c + 1) * 120]).expect("VAgg lane"));
        }
        let keyd = kagg_from_bytes(&k).expect("KAgg key");
        let alg_words = keyd.alg();
        rows.push(Row {
            fam: keyd.fam(),
            op: keyd.op(),
            res: keyd.res(),
            alg: cstr(&words_to_bytes(&alg_words)),
            val: fold_vagg(&lanes),
        });
        key = Some(k);
    }
    rows
}

/// Raw ring payload bytes (test-local mmap consumer; twin of the
/// `kcrypto_agg` drain, byte-scan shaped: no `KCtl` decode — the
/// canary scans payload bytes, never parses records).
fn drain_ring_bytes(sensor: &ConfiguredKcrypto) -> Vec<u8> {
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
            out.extend_from_slice(&data[off + 8..off + 8 + len]);
        }
        pos = pos.saturating_add(total as u64);
    }
    out
}

/// Raw bytes of every map + the ring (KCFG + all KAGG keys/values +
/// KTOT + all KIDN keys/values + ring payloads): the canary haystack.
fn dump_all_bytes(sensor: &ConfiguredKcrypto) -> Vec<u8> {
    let ncpu = possible_cpus() as usize;
    let mut out = Vec::new();
    out.extend_from_slice(
        &map_lookup_bytes(
            &sensor.loaded.maps.config,
            &0u32.to_le_bytes(),
            44,
            "canary/kcfg",
        )
        .expect("KCFG dump"),
    );
    let mut key: Option<Vec<u8>> = None;
    loop {
        let next = map_get_next_key(
            &sensor.loaded.maps.agg,
            key.as_deref(),
            260,
            "canary/kagg-keys",
        )
        .expect("KAGG iteration");
        let Some(k) = next else { break };
        out.extend_from_slice(&k);
        out.extend_from_slice(
            &map_lookup_bytes(&sensor.loaded.maps.agg, &k, 120 * ncpu, "canary/kagg-vals")
                .expect("KAGG lookup"),
        );
        key = Some(k);
    }
    out.extend_from_slice(
        &map_lookup_bytes(
            &sensor.loaded.maps.total,
            &0u32.to_le_bytes(),
            120 * ncpu,
            "canary/ktot",
        )
        .expect("KTOT dump"),
    );
    let mut key: Option<Vec<u8>> = None;
    loop {
        let next = map_get_next_key(
            &sensor.loaded.maps.ident,
            key.as_deref(),
            8,
            "canary/kidn-keys",
        )
        .expect("KIDN iteration");
        let Some(k) = next else { break };
        out.extend_from_slice(&k);
        out.extend_from_slice(
            &map_lookup_bytes(&sensor.loaded.maps.ident, &k, 1, "canary/kidn-vals")
                .expect("KIDN lookup"),
        );
        key = Some(k);
    }
    out.extend_from_slice(&drain_ring_bytes(sensor));
    out
}

/// Byte substring (never a string parse: the dumps are not UTF-8).
fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn kconfig_bytes_match_live_resolver() {
    // Unprivileged (BTF read only): the KCFG bytes the configured
    // entry writes equal the 9 live-resolved offsets + `PF_KTHREAD` +
    // zero pad in C2 word order.
    if !btf_available() {
        println!("SKIP: no /sys/kernel/btf/vmlinux on this host");
        return;
    }
    let off = resolve_offsets().expect("offsets must resolve");
    let bytes = kconfig_from_offsets(off).to_bytes();
    assert_eq!(bytes.len(), 44, "KCFG wire is 44B (C2 + shash_base)");
    let word =
        |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    assert_eq!(word(0), off.sk_req_base, "word 0: sk_req_base");
    assert_eq!(word(4), off.async_tfm, "word 1: async_tfm");
    assert_eq!(word(8), off.tfm_alg, "word 2: tfm_alg");
    assert_eq!(word(12), off.alg_name, "word 3: alg_name");
    assert_eq!(word(16), off.alg_drv, "word 4: alg_drv");
    assert_eq!(word(20), off.task_flags, "word 5: task_flags");
    assert_eq!(
        word(24),
        kryprobe_privilege::btf_resolve::PF_KTHREAD,
        "word 6: pf_kthread"
    );
    assert_eq!(word(28), off.aead_cryptlen_off, "word 7: aead_cryptlen_off");
    assert_eq!(word(32), off.ahash_nbytes_off, "word 8: ahash_nbytes_off");
    assert_eq!(word(36), off.shash_base, "word 9: shash_base");
    assert_eq!(word(40), 0, "word 10: zero pad");
}

/// Our bpffs pin dir (pid-suffixed: never collides, never shared).
fn pin_dir() -> PathBuf {
    PathBuf::from("/sys/fs/bpf").join(format!("k1t3probe-{}", std::process::id()))
}

/// Unlink guard: the pin file + dir vanish on all paths (RAII cleanup
/// for the bpffs side, which pins escape by design).
struct UnpinGuard {
    file: PathBuf,
    dir: PathBuf,
}

impl Drop for UnpinGuard {
    fn drop(&mut self) {
        std::fs::remove_file(&self.file).ok();
        std::fs::remove_dir(&self.dir).ok();
    }
}

#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn configured_entry_writes_kcfg_from_resolver() {
    if !lane_ready("configured_entry_writes_kcfg_from_resolver") {
        return;
    }
    let bytes = kcrypto_bytes();
    let (sensor, points) = load_kcrypto_configured(&bytes, None)
        .unwrap_or_else(|err| panic!("configured bring-up failed: {err}"));
    // All 9 points: loaded AND attached (per-point outcomes surfaced).
    assert_eq!(points.len(), 9, "the matrix is 9 points");
    for point in &points {
        assert!(
            matches!(point.load, PointStatus::Loaded { .. }),
            "{}: expected Loaded, got {:?}",
            point.name,
            point.load
        );
        assert_eq!(
            point.attach,
            Some(AttachOutcome::Attached),
            "{}: expected Attached, got {:?}",
            point.name,
            point.attach
        );
    }
    assert_eq!(sensor.links.len(), 9, "9 live links");
    assert_eq!(sensor.loaded.progs.len(), 9, "9 loaded programs");
    // The KCFG row reads back byte-identical to the resolver's bytes.
    let want = kconfig_from_offsets(resolve_offsets().expect("offsets must resolve")).to_bytes();
    let got = map_lookup_bytes(
        &sensor.loaded.maps.config,
        &0u32.to_le_bytes(),
        44,
        "configured/kcfg",
    )
    .expect("KCFG read");
    assert_eq!(got, want, "KCFG must equal the resolver's bytes");
    // From the pinned map too (bpffs-writability skips only this step:
    // the fd read-back above is the unconditional injection proof).
    let dir = pin_dir();
    if let Err(err) = std::fs::create_dir(&dir) {
        let errno = err.raw_os_error().unwrap_or(0);
        if [libc::EPERM, libc::EACCES, libc::EROFS].contains(&errno) {
            println!("SKIP: bpffs not writable (errno {errno})");
            return;
        }
        panic!("cannot create pin dir {}: {err}", dir.display());
    }
    {
        let _guard = UnpinGuard {
            file: dir.join("KCFG"),
            dir: dir.clone(),
        };
        pin_fd(&sensor.loaded.maps.config, &dir, "KCFG")
            .unwrap_or_else(|err| panic!("pin KCFG failed: {err}"));
        assert!(dir.join("KCFG").exists(), "pin file must exist after pin");
        let pinned = map_lookup_bytes(
            &sensor.loaded.maps.config,
            &0u32.to_le_bytes(),
            44,
            "configured/kcfg-pinned",
        )
        .expect("KCFG pinned read");
        assert_eq!(pinned, want, "pinned KCFG must equal the resolver's bytes");
    }
    assert!(
        !dir.exists(),
        "pin dir must be gone after cleanup: {}",
        dir.display()
    );
}

#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn canary_kcrypto() {
    // The fixture buffers must carry the needle, or the scan is vacuous
    // (a fixture refactor dropping the markers fails HERE, loudly).
    assert!(
        alg_fixture::CANARY_KEY.starts_with(NEEDLE),
        "canary key must start with the needle"
    );
    assert!(
        alg_fixture::CANARY_IV.starts_with(NEEDLE),
        "canary IV must start with the needle"
    );
    assert!(
        alg_fixture::CANARY_PT.starts_with(NEEDLE),
        "canary plaintext must start with the needle"
    );
    if !lane_ready("canary_kcrypto") {
        return;
    }
    let bytes = kcrypto_bytes();
    let (sensor, points) = load_kcrypto_configured(&bytes, None)
        .unwrap_or_else(|err| panic!("configured bring-up failed: {err}"));
    assert!(
        points
            .iter()
            .all(|p| p.attach == Some(AttachOutcome::Attached)),
        "all 9 must attach: {points:?}"
    );
    let counts = alg_fixture::skcipher_canary_roundtrip("cbc(aes)", 20).expect("canary traffic");
    assert_eq!((counts.enc, counts.dec), (20, 20));
    // Positive control: the sensor SAW the canary ops (an unconfigured
    // sensor would pass the absence scan trivially — this blocks that).
    let rows = dump_kagg_rows(&sensor);
    for (op, what) in [(KOP_ENC, "enc"), (KOP_DEC, "dec")] {
        let mut calls = 0u64;
        for row in rows
            .iter()
            .filter(|r| r.fam == KFAM_SK && r.op == op && r.res == KRES_OK && r.alg == "cbc(aes)")
        {
            calls = calls.saturating_add(row.val.calls);
        }
        assert_eq!(calls, 20, "canary {what} calls observed");
    }
    // The ring dump path is live (alloc IDENT at minimum).
    let ring = drain_ring_bytes(&sensor);
    assert!(!ring.is_empty(), "ring must carry canary IDENTs");
    // Absence: no canary marker byte-sequence anywhere in the dumps.
    let hay = dump_all_bytes(&sensor);
    assert!(
        !hay.is_empty(),
        "haystack must be non-empty (dumps actually read)"
    );
    assert!(
        !contains_bytes(&hay, NEEDLE),
        "canary marker leaked into KAGG/KTOT/KIDN/KRING/KCFG dumps ({} bytes scanned)",
        hay.len()
    );
}
