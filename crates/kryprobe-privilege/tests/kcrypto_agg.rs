// SPDX-License-Identifier: GPL-3.0-or-later
//! K1 Task 2: kcrypto sensor exactness — privileged P4-method proof.
//!
//! Each test loads the true 9-prog fexit object, inits `KCFG` from the
//! live resolver, attaches all 9, runs committed fixture traffic
//! ([`kryprobe_testkit::alg_fixture`]), and compares sensor deltas
//! against fixture-reported truth (never against requested inputs).
//! Map reads are independent (raw `BPF_MAP_*` via the loader's own map
//! fds — the k0load-style dump, committed this time).
//!
//! Parallelism: tests run in parallel threads, and every sensor instance
//! is system-wide — so each test uses a DISTINCT algorithm and matches
//! rows by decoded identity (multi-row find/sum). Cross-test traffic
//! lands in other rows; background host crypto (none observed) would
//! too. `KTOT` assertions are therefore conservation-shaped
//! (`KTOT == ΣKAGG`, lower bounds), never exact equality with fixture
//! counts.
//!
//! Honest skips: every privileged test returns early (not `#[ignore]`d
//! out — they run and print `SKIP`) when not root or when BTF is
//! missing. The C3 re-verification needs only BTF and runs everywhere.

use kryprobe_abi::kcrypto_agg::{
    KCTL_GAP, KCTL_GENCHANGE, KCTL_HEALTH, KCTL_IDENT, KCTL_OVERFLOW, KCTX_SOFTIRQ, KConfig, KCtl,
    KFAM_AEAD, KFAM_AHASH, KFAM_ANY, KFAM_SHASH, KFAM_SK, KIDN_DROPS, KOP_ALLOC, KOP_DEC,
    KOP_DIGEST, KOP_ENC, KOP_FINUP, KRES_ERR, KRES_OK, VAgg, fold_vagg, kagg_from_bytes,
    kcrypto_ident_hash, kctl_from_bytes, kctl_pack_head, kctl_pack_lens, vagg_from_bytes,
};
use kryprobe_core::attach::{CookieAllocator, GenerationGuard, LinkGroup};
use kryprobe_core::authority::AttachAuthority;
use kryprobe_core::ids::PlanGeneration;
use kryprobe_core::object::{ObjectRef, ObjectRole};
use kryprobe_core::plan::TargetScope;
use kryprobe_core::program::ProgramId;
use kryprobe_privilege::LocalPrivilegedAuthority;
use kryprobe_privilege::attach::OwnedLink;
use kryprobe_privilege::bpfloader::{LoadedKcrypto, load_kcrypto};
use kryprobe_privilege::btf_resolve::{
    FIRST_MEMBER_LINKS, KCRYPTO_SYMBOLS, PF_KTHREAD, resolve_aggregate_offsets, resolve_btf_ids,
    resolve_member_offset,
};
use kryprobe_privilege::mapops::{
    map_get_next_key, map_lookup_bytes, map_update_bytes, possible_cpus,
};
use kryprobe_testkit::alg_fixture;
use std::path::{Path, PathBuf};

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

/// Privileged-gate: true when this test must run (root + BTF + object).
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

fn object() -> ObjectRef {
    ObjectRef {
        dev: 0,
        ino: 0,
        size: 0,
        mtime: 0,
        role: ObjectRole::Executable,
    }
}

/// Loaded + configured + attached sensor (RAII: drop detaches everything).
struct Sensor {
    loaded: LoadedKcrypto,
    /// Held (never read): dropping detaches.
    #[allow(dead_code)]
    links: Vec<OwnedLink>,
}

impl Sensor {
    /// Load once with all 9 ids, init `KCFG` from the live resolver,
    /// attach all 9. Panics (with stage context) on any failure.
    fn attach() -> Self {
        let bytes = kcrypto_bytes();
        let ids = resolve_btf_ids().expect("P0 symbols must resolve");
        let entries: Vec<(String, u32)> = KCRYPTO_SYMBOLS
            .iter()
            .map(|name| ((*name).to_owned(), ids[*name]))
            .collect();
        let (loaded, statuses) = load_kcrypto(&bytes, &entries, None).expect("9-prog load");
        assert_eq!(statuses.len(), 9);
        assert!(
            statuses
                .iter()
                .all(|s| matches!(s, kryprobe_privilege::bpfloader::PointStatus::Loaded { .. })),
            "all 9 must load: {statuses:?}"
        );
        assert_eq!(loaded.progs.len(), 9);
        let off = resolve_aggregate_offsets().expect("offsets must resolve");
        let cfg = KConfig {
            sk_req_base: off.sk_req_base,
            async_tfm: off.async_tfm,
            tfm_alg: off.tfm_alg,
            alg_name: off.alg_name,
            alg_drv: off.alg_drv,
            task_flags: off.task_flags,
            pf_kthread: PF_KTHREAD,
            aead_cryptlen_off: off.aead_cryptlen_off,
            ahash_nbytes_off: off.ahash_nbytes_off,
            shash_base: off.shash_base,
            _pad: 0,
            // K5 attribution tail, zeroed (Task 3 wires resolution).
            task_real_parent: 0,
            task_tgid: 0,
            task_comm: 0,
            cra_blocksize: 0,
            cra_ivsize: 0,
            cra_min_keysize: 0,
            cra_max_keysize: 0,
            parent_ok: 0,
            params_ok: 0,
            _pad2: [0, 0],
        };
        map_update_bytes(
            &loaded.maps.config,
            &0u32.to_le_bytes(),
            &cfg.to_bytes(),
            "kcrypto_agg/kcfg",
        )
        .expect("KCFG init");
        let mut alloc = CookieAllocator::new(PlanGeneration::new(1));
        let mut links = Vec::with_capacity(9);
        for (name, prog) in &loaded.progs {
            let range = alloc.allocate(1).expect("group range fits");
            let group = LinkGroup::from_range(
                object(),
                ProgramId::UprobeMultiSelfProbe,
                TargetScope::System,
                true,
                range,
            );
            let guard = GenerationGuard {
                generation: PlanGeneration::new(1),
            };
            let link = LocalPrivilegedAuthority
                .attach_group(&group, &guard, prog, Path::new(""), &[])
                .unwrap_or_else(|err| panic!("attach {name}: {err}"));
            links.push(link);
        }
        assert_eq!(links.len(), 9);
        Self { loaded, links }
    }
}

/// One dumped `KAGG` row: decoded attribution + names + folded value.
struct AggRow {
    fam: u8,
    op: u8,
    res: u8,
    ctx: u8,
    alg: String,
    drv: String,
    /// Raw identity words (for the hash join).
    alg_words: [u64; 16],
    drv_words: [u64; 16],
    val: VAgg,
}

impl AggRow {
    fn ident_hash(&self) -> u64 {
        kcrypto_ident_hash(self.fam, self.op, &self.alg_words, &self.drv_words)
    }
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

/// Dump every `KAGG` row (key iteration + per-CPU fold).
fn dump_kagg(sensor: &Sensor) -> Vec<AggRow> {
    let ncpu = possible_cpus() as usize;
    let mut rows = Vec::new();
    let mut key: Option<Vec<u8>> = None;
    loop {
        // SAFETY: KAGG key is KAgg, exactly 260B.
        let next =
            unsafe { map_get_next_key(&sensor.loaded.maps.agg, key.as_deref(), 260, "kagg/iter") }
                .expect("KAGG iteration");
        let Some(k) = next else { break };
        assert_eq!(k.len(), 260, "KAGG key size drifted");
        // SAFETY: KAGG value is VAgg, 120B × possible_cpus.
        let raw = unsafe { map_lookup_bytes(&sensor.loaded.maps.agg, &k, 120 * ncpu, "kagg/val") }
            .expect("KAGG lookup");
        let mut lanes = Vec::with_capacity(ncpu);
        for c in 0..ncpu {
            lanes.push(vagg_from_bytes(&raw[c * 120..(c + 1) * 120]).expect("VAgg lane"));
        }
        let keyd = kagg_from_bytes(&k).expect("KAgg key");
        let alg_words = keyd.alg();
        let drv_words = keyd.drv();
        rows.push(AggRow {
            fam: keyd.fam(),
            op: keyd.op(),
            res: keyd.res(),
            ctx: keyd.ctx(),
            alg: cstr(&words_to_bytes(&alg_words)),
            drv: cstr(&words_to_bytes(&drv_words)),
            alg_words,
            drv_words,
            val: fold_vagg(&lanes),
        });
        key = Some(k);
    }
    rows
}

/// Fold the single `KTOT` row.
fn dump_ktot(sensor: &Sensor) -> VAgg {
    let ncpu = possible_cpus() as usize;
    // SAFETY: KTOT value is VAgg, 120B × possible_cpus.
    let raw = unsafe {
        map_lookup_bytes(
            &sensor.loaded.maps.total,
            &0u32.to_le_bytes(),
            120 * ncpu,
            "ktot/val",
        )
    }
    .expect("KTOT lookup");
    let mut lanes = Vec::with_capacity(ncpu);
    for c in 0..ncpu {
        lanes.push(vagg_from_bytes(&raw[c * 120..(c + 1) * 120]).expect("KTOT lane"));
    }
    fold_vagg(&lanes)
}

/// Count `KIDN` entries (+ read the drops counter, 0 when absent).
fn dump_kidn(sensor: &Sensor) -> (usize, u8) {
    let mut count = 0;
    let mut key: Option<Vec<u8>> = None;
    loop {
        // SAFETY: KIDN key is u64, exactly 8B.
        let next =
            unsafe { map_get_next_key(&sensor.loaded.maps.ident, key.as_deref(), 8, "kidn/iter") }
                .expect("KIDN iteration");
        let Some(k) = next else { break };
        count += 1;
        key = Some(k);
    }
    // SAFETY: KIDN value is u8; value_len 1 is exact.
    let drops = unsafe {
        map_lookup_bytes(
            &sensor.loaded.maps.ident,
            &KIDN_DROPS.to_le_bytes(),
            1,
            "kidn/drops",
        )
    }
    .map(|v| v[0])
    .unwrap_or(0);
    (count, drops)
}

/// Drain `KRING` (test-local mmap consumer; read-only snapshot — the
/// consumer position is left alone since every test owns fresh maps).
fn drain_ring(sensor: &Sensor) -> Vec<KCtl> {
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
            let rec = &data[off + 8..off + 8 + len];
            out.push(
                kctl_from_bytes(rec)
                    .unwrap_or_else(|| panic!("ring record is not a 48B KCtl (len={len})")),
            );
        }
        pos = pos.saturating_add(total as u64);
    }
    out
}

/// Sum rows matching `(fam, op, res, alg)` over all contexts (the P4
/// find/sum: background + cross-test traffic lives in other rows).
/// Rows match by NUL-terminated string: requested-name hashes are
/// cross-run unstable (heap padding past NUL is hashed).
fn sum_rows(rows: &[AggRow], fam: u8, op: u8, res: u8, alg: &str) -> VAgg {
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

/// `ok + errors + queued == calls` on every row (the conservation law;
/// destroy rows are exempt — none exist — see the BPF limitation note).
fn assert_conservation(rows: &[AggRow], what: &str) {
    for row in rows {
        let sum = row.val.ok + row.val.errors + row.val.queued;
        assert_eq!(
            sum, row.val.calls,
            "{what}: row fam={} op={} res={} ctx={} alg={:?} breaks conservation ({sum} != {})",
            row.fam, row.op, row.res, row.ctx, row.alg, row.val.calls
        );
    }
}

/// C4/C6/C7 honest zeros: `lat` all zero, no softirq rows, only
/// IDENT/OVERFLOW kinds on the ring.
fn assert_honest_zeros(rows: &[AggRow], ring: &[KCtl], what: &str) {
    for row in rows {
        assert_eq!(
            row.val.lat, [0; 8],
            "{what}: lat nonzero on fam={} op={} alg={:?}",
            row.fam, row.op, row.alg
        );
        assert_ne!(
            row.ctx, KCTX_SOFTIRQ,
            "{what}: softirq row exists (fam={} op={} alg={:?})",
            row.fam, row.op, row.alg
        );
    }
    for ctl in ring {
        assert!(
            ctl.kind == KCTL_IDENT || ctl.kind == KCTL_OVERFLOW,
            "{what}: reserved ring kind {} emitted",
            ctl.kind
        );
        assert!(
            ctl.kind != KCTL_GENCHANGE && ctl.kind != KCTL_GAP && ctl.kind != KCTL_HEALTH,
            "{what}: reserved kind {} must stay zero-pinned",
            ctl.kind
        );
    }
}

/// C5 ring join: every IDENT references a dumped row by hash, with
/// consistent packed head/lengths/first-seen window.
///
/// Multi-row gates (several rows sharing one `(fam, op, alg, drv)` gate
/// via distinct `res`/`ctx` — e.g. dec-OK + dec-ERR): the IDENT carries
/// the FIRST-SEEN row's head, which need not be the dump-order-first
/// match — so the head must equal SOME row's head, and the `ns` must
/// fall in the UNION window across the gate's rows.
fn assert_ident_join(rows: &[AggRow], ring: &[KCtl], what: &str) {
    for ctl in ring.iter().filter(|c| c.kind == KCTL_IDENT) {
        let gated: Vec<&AggRow> = rows
            .iter()
            .filter(|r| r.ident_hash() == ctl.key_hash)
            .collect();
        assert!(
            !gated.is_empty(),
            "{what}: IDENT {:016x} joins no dumped row ({} rows)",
            ctl.key_hash,
            rows.len()
        );
        let heads: Vec<u64> = gated
            .iter()
            .map(|r| kctl_pack_head(r.fam, r.op, r.res, r.ctx))
            .collect();
        assert!(
            heads.contains(&ctl.val0),
            "{what}: IDENT head {:#x} matches no row of gate {:016x} ({heads:?})",
            ctl.val0,
            ctl.key_hash
        );
        // Lengths are gate-uniform (same names on every row).
        let (alg_len, drv_len) = (gated[0].alg.len() as u32, gated[0].drv.len() as u32);
        assert_eq!(
            ctl.val1,
            kctl_pack_lens(alg_len, drv_len),
            "{what}: IDENT lens mismatch for {:016x}",
            ctl.key_hash
        );
        let first = gated.iter().map(|r| r.val.first_ns).min().unwrap_or(0);
        let last = gated.iter().map(|r| r.val.last_ns).max().unwrap_or(0);
        assert!(
            first <= ctl.val2 && ctl.val2 <= last,
            "{what}: IDENT ns {} outside gate window [{first}, {last}]",
            ctl.val2
        );
        assert_eq!(ctl.val3, 0, "{what}: IDENT val3 must be reserved zero");
    }
}

/// Suite serialization lock: the sensors are system-wide, so parallel
/// tests' traffic would race each other's dumps (`KTOT` vs `ΣKAGG` is
/// exact only under quiescence). Each privileged test holds this across
/// its whole body (attach→detach), making sensor lifetimes disjoint;
/// per-identity find/sum additionally isolates each test's own traffic.
/// Poison-tolerant: a failed test must not cascade into lock errors.
static SUITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn suite_guard() -> std::sync::MutexGuard<'static, ()> {
    SUITE_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

/// `KTOT == ΣKAGG` over ALL dumped rows (totals conservation; holds
/// exactly when neither map overflowed — asserted overflow-free first).
fn assert_totals_conservation(rows: &[AggRow], tot: &VAgg, what: &str) {
    let mut sum = VAgg::default();
    for row in rows {
        sum.calls = sum.calls.saturating_add(row.val.calls);
        sum.bytes = sum.bytes.saturating_add(row.val.bytes);
        sum.ok = sum.ok.saturating_add(row.val.ok);
        sum.errors = sum.errors.saturating_add(row.val.errors);
        sum.queued = sum.queued.saturating_add(row.val.queued);
    }
    assert_eq!(tot.calls, sum.calls, "{what}: KTOT.calls != ΣKAGG");
    assert_eq!(tot.bytes, sum.bytes, "{what}: KTOT.bytes != ΣKAGG");
    assert_eq!(tot.ok, sum.ok, "{what}: KTOT.ok != ΣKAGG");
    assert_eq!(tot.errors, sum.errors, "{what}: KTOT.errors != ΣKAGG");
    assert_eq!(tot.queued, sum.queued, "{what}: KTOT.queued != ΣKAGG");
}

/// No-overflow gate: no `OVERFLOW` ring event, drops counter zero, and
/// small maps (far from the 256-entry caps). Call BEFORE any fold that
/// assumes overflow-freedom (totals conservation, exactness).
fn assert_no_overflow(sensor: &Sensor, ring: &[KCtl], what: &str) {
    assert!(
        ring.iter().all(|c| c.kind != KCTL_OVERFLOW),
        "{what}: OVERFLOW ring event present"
    );
    let (kidn_count, drops) = dump_kidn(sensor);
    assert_eq!(drops, 0, "{what}: ring-reserve drops counter nonzero");
    assert!(
        kidn_count < 64,
        "{what}: KIDN unexpectedly large ({kidn_count})"
    );
}

#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn skcipher_exactness() {
    let _guard = suite_guard();
    if !lane_ready("skcipher_exactness") {
        return;
    }
    let sensor = Sensor::attach();
    let counts = alg_fixture::skcipher_roundtrip("cbc(aes)", 50).expect("skcipher traffic");
    assert_eq!((counts.enc, counts.dec), (50, 50));
    let rows = dump_kagg(&sensor);
    let tot = dump_ktot(&sensor);
    let ring = drain_ring(&sensor);
    assert_no_overflow(&sensor, &ring, "skcipher");
    // Per-identity exactness (P4: fixture truth vs sensor delta).
    // BOUNDED 48..=50 (G9 kworker-miss finding: cbc(aes) is
    // cryptd-async here and ~1% of kworker completions never reach BPF
    // — see the kcrypto_driver comment + evidence/review-remain/
    // g9-kworker-miss/). Shape stays exact.
    let enc = sum_rows(&rows, KFAM_SK, KOP_ENC, KRES_OK, "cbc(aes)");
    assert!(
        (48..=50).contains(&enc.calls) && enc.bytes == enc.calls * 32 && enc.ok == enc.calls,
        "sk enc bounded 48..=50 with exact shape: {enc:?}"
    );
    assert_eq!(enc.errors, 0, "sk enc errors");
    assert_eq!(
        enc.queued, 0,
        "sk enc queued (ok cell carries no queued subcount)"
    );
    let dec = sum_rows(&rows, KFAM_SK, KOP_DEC, KRES_OK, "cbc(aes)");
    assert!(
        (48..=50).contains(&dec.calls) && dec.bytes == dec.calls * 32 && dec.ok == dec.calls,
        "sk dec bounded 48..=50 with exact shape: {dec:?}"
    );
    let alloc = sum_rows(&rows, KFAM_ANY, KOP_ALLOC, KRES_OK, "cbc(aes)");
    assert_eq!(alloc.calls, 1, "sk alloc calls (one bind)");
    assert_eq!(alloc.bytes, 0, "alloc carries no bytes");
    // Error rows for this identity must not exist (clean roundtrip).
    let enc_err = sum_rows(&rows, KFAM_SK, KOP_ENC, KRES_ERR, "cbc(aes)");
    let dec_err = sum_rows(&rows, KFAM_SK, KOP_DEC, KRES_ERR, "cbc(aes)");
    assert_eq!(
        enc_err.calls + dec_err.calls,
        0,
        "no error rows on clean traffic"
    );
    assert_conservation(&rows, "skcipher");
    assert_totals_conservation(&rows, &tot, "skcipher");
    assert_honest_zeros(&rows, &ring, "skcipher");
    assert_ident_join(&rows, &ring, "skcipher");
    // First/last stamps are seen-edge stamps inside the run window.
    for row in &rows {
        assert!(
            row.val.first_ns > 0 && row.val.first_ns <= row.val.last_ns,
            "skcipher: bad stamps on {:?}/{}",
            row.alg,
            row.op
        );
    }
}

#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn aead_exactness_and_bad_tag_errors() {
    let _guard = suite_guard();
    if !lane_ready("aead_exactness_and_bad_tag_errors") {
        return;
    }
    if !alg_fixture::aead_alg_available("gcm(aes)") {
        println!(
            "SKIP: aead_exactness_and_bad_tag_errors requires an AEAD alg (none bind on this kernel)"
        );
        return;
    }
    let sensor = Sensor::attach();
    let counts = alg_fixture::aead_roundtrip("gcm(aes)", 10).expect("aead traffic");
    assert_eq!((counts.enc, counts.dec), (10, 10));
    alg_fixture::aead_decrypt_bad_tag("gcm(aes)").expect("bad-tag decrypt must EBADMSG");
    let rows = dump_kagg(&sensor);
    let tot = dump_ktot(&sensor);
    let ring = drain_ring(&sensor);
    assert_no_overflow(&sensor, &ring, "aead");
    // N=10 clean roundtrip + 1 bad-tag encrypt + 1 bad-tag (failed) decrypt.
    let enc = sum_rows(&rows, KFAM_AEAD, KOP_ENC, KRES_OK, "gcm(aes)");
    assert_eq!(enc.calls, 11, "aead enc calls (10 + bad-tag setup)");
    assert_eq!(enc.bytes, 11 * 32, "aead enc bytes (C2 cryptlen)");
    assert_eq!(enc.ok, 11, "aead enc ok");
    let dec = sum_rows(&rows, KFAM_AEAD, KOP_DEC, KRES_OK, "gcm(aes)");
    assert_eq!(dec.calls, 10, "aead dec calls");
    assert_eq!(dec.bytes, 10 * 48, "aead dec bytes (cryptlen incl. tag)");
    assert_eq!(dec.ok, 10, "aead dec ok");
    // The errors bucket, proven live: the bad-tag decrypt classified ERR.
    let dec_err = sum_rows(&rows, KFAM_AEAD, KOP_DEC, KRES_ERR, "gcm(aes)");
    assert_eq!(dec_err.calls, 1, "bad-tag decrypt observed");
    assert_eq!(dec_err.errors, 1, "bad-tag decrypt classified errors");
    assert_eq!(dec_err.ok, 0, "bad-tag decrypt not ok");
    assert_eq!(
        dec_err.bytes, 48,
        "bad-tag decrypt bytes (failed leg still sized)"
    );
    assert_eq!(dec_err.queued, 0, "no queued on sync host");
    assert_conservation(&rows, "aead");
    assert_totals_conservation(&rows, &tot, "aead");
    assert_honest_zeros(&rows, &ring, "aead");
    assert_ident_join(&rows, &ring, "aead");
}

#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn hash_points_observed() {
    let _guard = suite_guard();
    if !lane_ready("hash_points_observed") {
        return;
    }
    let prepared = alg_fixture::PreparedHashFinups::new("sha256").expect("prepare hash prefix");
    let sensor = Sensor::attach();
    let single = alg_fixture::hash_digest("sha256", 10).expect("hash traffic");
    assert_eq!(single.digests, 10);
    assert_eq!(single.digest_len, 32);
    let multi = prepared
        .finish(6)
        .expect("cloned finup traffic and digest goldens");
    assert_eq!((multi.digests, multi.digest_len), (6, 32));
    let rows = dump_kagg(&sensor);
    let tot = dump_ktot(&sensor);
    let ring = drain_ring(&sensor);
    assert_no_overflow(&sensor, &ring, "hash");
    // Single-shot digest: one ahash + one shash observation per op,
    // each sized 64B (C2 nbytes / shash len arg).
    let ahash = sum_rows(&rows, KFAM_AHASH, KOP_DIGEST, KRES_OK, "sha256");
    assert_eq!(ahash.calls, 10, "ahash digest calls");
    assert_eq!(ahash.bytes, 10 * 64, "ahash digest bytes");
    assert_eq!(ahash.ok, 10, "ahash digest ok");
    let shash = sum_rows(&rows, KFAM_SHASH, KOP_DIGEST, KRES_OK, "sha256");
    assert_eq!(shash.calls, 10, "shash digest calls");
    assert_eq!(shash.bytes, 10 * 64, "shash digest bytes (len arg)");
    assert_eq!(shash.ok, 10, "shash digest ok");
    // Prepared prefix is outside capture. One finup per clone on the
    // qualified shash route, sized only by its 16-byte final argument.
    let finup = sum_rows(&rows, KFAM_SHASH, KOP_FINUP, KRES_OK, "sha256");
    assert_eq!(finup.calls, 6, "one finup per clone");
    assert_eq!(finup.bytes, 6 * 16, "finup argument bytes, not full input");
    assert_eq!(finup.ok, 6, "finup ok");
    assert_eq!((finup.errors, finup.queued), (0, 0));
    // Global counts cannot be satisfied by foreign traffic replacing a
    // missing owned call. Join each finup row to its full KWHO identity.
    for row in rows
        .iter()
        .filter(|r| r.fam == KFAM_SHASH && r.op == KOP_FINUP && r.alg == "sha256")
    {
        use kryprobe_abi::kcrypto_agg::{kh_of, kwho_key_from_bytes, vwho_from_bytes};
        let hash = kh_of(
            row.fam,
            row.op,
            row.res,
            row.ctx,
            &row.alg_words,
            &row.drv_words,
        );
        let mut key = None;
        let mut owned_calls = 0;
        loop {
            // SAFETY: KWHO keys are 16 bytes, values 80 bytes per possible CPU.
            let next = unsafe {
                map_get_next_key(&sensor.loaded.maps.who, key.as_deref(), 16, "hash/who-key")
            }
            .expect("caller keys");
            let Some(k) = next else { break };
            let identity = kwho_key_from_bytes(&k).expect("caller key layout");
            if identity.kh == hash {
                let raw = unsafe {
                    map_lookup_bytes(
                        &sensor.loaded.maps.who,
                        &k,
                        80 * possible_cpus() as usize,
                        "hash/who-value",
                    )
                }
                .expect("caller values");
                let calls: u64 = raw
                    .as_chunks::<80>()
                    .0
                    .iter()
                    .map(|lane| vwho_from_bytes(lane).expect("caller value layout").calls)
                    .sum();
                assert_eq!(
                    identity.tgid,
                    std::process::id(),
                    "foreign finup traffic cannot satisfy the fixture"
                );
                owned_calls += calls;
            }
            key = Some(k);
        }
        assert_eq!(
            owned_calls, row.val.calls,
            "finup callers reconcile to aggregate"
        );
    }
    assert_conservation(&rows, "hash");
    assert_totals_conservation(&rows, &tot, "hash");
    assert_honest_zeros(&rows, &ring, "hash");
    assert_ident_join(&rows, &ring, "hash");
}

#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn burst_exactness_near_million() {
    let _guard = suite_guard();
    if !lane_ready("burst_exactness_near_million") {
        return;
    }
    let sensor = Sensor::attach();
    // Distinct alg from the skcipher test (parallel-run isolation).
    let burst = alg_fixture::burst_encrypt("ctr(aes)", 10).expect("burst traffic");
    assert!(
        burst.ops > 100_000,
        "burst made sensible progress: {}",
        burst.ops
    );
    let rows = dump_kagg(&sensor);
    let tot = dump_ktot(&sensor);
    let ring = drain_ring(&sensor);
    assert_no_overflow(&sensor, &ring, "burst");
    // P4 at scale: the sensor delta equals fixture truth EXACTLY.
    let enc = sum_rows(&rows, KFAM_SK, KOP_ENC, KRES_OK, "ctr(aes)");
    assert_eq!(enc.calls, burst.ops, "burst enc calls == fixture truth");
    assert_eq!(
        enc.bytes,
        burst.ops * 4096,
        "burst enc bytes == ops * 4KiB (no sampling, no drops)"
    );
    assert_eq!(enc.ok, burst.ops, "burst enc ok");
    assert_eq!(enc.errors + enc.queued, 0, "burst clean buckets");
    assert_conservation(&rows, "burst");
    assert_totals_conservation(&rows, &tot, "burst");
    assert_honest_zeros(&rows, &ring, "burst");
    assert_ident_join(&rows, &ring, "burst");
}

#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn kcfg_roundtrip_matches_resolver() {
    let _guard = suite_guard();
    if !lane_ready("kcfg_roundtrip_matches_resolver") {
        return;
    }
    // Load only (no attach, no traffic): the 76B KCFG row the loader
    // path writes must read back byte-identical (pin + codec + dims).
    let bytes = kcrypto_bytes();
    let ids = resolve_btf_ids().expect("P0 symbols must resolve");
    let entries: Vec<(String, u32)> = KCRYPTO_SYMBOLS
        .iter()
        .map(|name| ((*name).to_owned(), ids[*name]))
        .collect();
    let (loaded, _) = load_kcrypto(&bytes, &entries, None).expect("load for KCFG roundtrip");
    let off = resolve_aggregate_offsets().expect("offsets must resolve");
    let cfg = KConfig {
        sk_req_base: off.sk_req_base,
        async_tfm: off.async_tfm,
        tfm_alg: off.tfm_alg,
        alg_name: off.alg_name,
        alg_drv: off.alg_drv,
        task_flags: off.task_flags,
        pf_kthread: PF_KTHREAD,
        aead_cryptlen_off: off.aead_cryptlen_off,
        ahash_nbytes_off: off.ahash_nbytes_off,
        shash_base: off.shash_base,
        _pad: 0,
        // K5 attribution tail, zeroed (Task 3 wires resolution).
        task_real_parent: 0,
        task_tgid: 0,
        task_comm: 0,
        cra_blocksize: 0,
        cra_ivsize: 0,
        cra_min_keysize: 0,
        cra_max_keysize: 0,
        parent_ok: 0,
        params_ok: 0,
        _pad2: [0, 0],
    };
    let want = cfg.to_bytes();
    assert_eq!(
        want.len(),
        76,
        "KCFG wire is 76B (C2 + shash_base + K5 tail)"
    );
    map_update_bytes(
        &loaded.maps.config,
        &0u32.to_le_bytes(),
        &want,
        "kcfg/roundtrip",
    )
    .expect("KCFG write");
    // SAFETY: KCFG wire is exactly 76B (asserted above).
    let got = unsafe {
        map_lookup_bytes(
            &loaded.maps.config,
            &0u32.to_le_bytes(),
            76,
            "kcfg/roundtrip",
        )
    }
    .expect("KCFG read");
    assert_eq!(got, want, "KCFG must roundtrip byte-identical");
}

#[test]
fn c3_first_member_links_reverified() {
    // Unprivileged (BTF read only): re-verifies every C3 literal-0 link
    // from LIVE BTF and fails closed on any nonzero (same walker the
    // loader asserts with — a kernel struct reorder breaks loudly here
    // instead of mis-chasing in BPF).
    if !btf_available() {
        println!("SKIP: no /sys/kernel/btf/vmlinux on this host");
        return;
    }
    assert_eq!(
        FIRST_MEMBER_LINKS.len(),
        4,
        "four C3 links (shash retired to resolution)"
    );
    for (type_name, member) in FIRST_MEMBER_LINKS {
        let offset = resolve_member_offset(type_name, member)
            .unwrap_or_else(|err| panic!("C3 resolve {type_name}.{member}: {err}"));
        assert_eq!(
            offset, 0,
            "C3 first-member link {type_name}.{member} moved to byte {offset} (BPF hardcodes 0)"
        );
    }
}
