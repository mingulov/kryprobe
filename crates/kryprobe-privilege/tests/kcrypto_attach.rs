// SPDX-License-Identifier: GPL-3.0-or-later
//! K1 Task 2: kcrypto sensor proof — parse shape, BTF resolution
//! (unprivileged), and the privileged 9-point attach matrix.
//!
//! Pure tests (parse, pin gate, resolver) run everywhere, including
//! `cargo xtask check`. The two `#[ignore]`d lane tests need root +
//! objects (`cargo xtask test bpf`) and skip honestly otherwise
//! (`token_plumbing` idiom). The attach matrix loads the true 9-prog
//! fexit object ONCE with all 9 `attach_btf_id`s (each program binds
//! its own section suffix) and asserts 9 live links through the
//! loader's own handles plus procfs fd kinds (no bpftool oracle).

use kryprobe_core::attach::{CookieAllocator, GenerationGuard, LinkGroup};
use kryprobe_core::authority::AttachAuthority;
use kryprobe_core::ids::PlanGeneration;
use kryprobe_core::object::{ObjectRef, ObjectRole};
use kryprobe_core::plan::TargetScope;
use kryprobe_core::program::ProgramId;
use kryprobe_privilege::LocalPrivilegedAuthority;
use kryprobe_privilege::bpfloader::{
    KCRYPTO_MAPS, LoaderError, PointStatus, check_pin_name, load_kcrypto, parse_kcrypto_object,
    parse_spine_object, pin_fd,
};
use kryprobe_privilege::btf_resolve::{
    KCRYPTO_SYMBOLS, resolve_aggregate_offsets, resolve_btf_ids, resolve_lifecycle_offsets,
};
use std::collections::HashSet;
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

/// Workspace-relative path of the built spine object.
fn spine_object_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("kryprobe-bpf")
        .join("spine.bpf.o")
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

fn spine_bytes() -> Vec<u8> {
    let path = spine_object_path();
    assert!(
        path.is_file(),
        "missing BPF spine object at {} — run `cargo xtask build --bpf`",
        path.display()
    );
    std::fs::read(&path).expect("test fixture must be readable")
}

#[test]
fn kcrypto_object_present() {
    let path = kcrypto_object_path();
    assert!(
        path.is_file(),
        "missing BPF kcrypto object at {} — run `cargo xtask build --bpf`",
        path.display()
    );
}

#[test]
fn parse_reports_kcrypto_dims() {
    let bytes = kcrypto_bytes();
    let parsed = parse_kcrypto_object(&bytes).expect("real object must parse");
    assert_eq!(parsed.maps.len(), KCRYPTO_MAPS.len(), "map count drifted");
    for ((want_name, want_dims), got) in KCRYPTO_MAPS.iter().zip(parsed.maps.iter()) {
        assert_eq!(got.name, *want_name);
        assert_eq!(got.dims, *want_dims, "dims drifted for {want_name}");
    }
    assert_eq!(parsed.maps.len(), 10);
}

#[test]
fn parse_finds_nine_fexit_programs() {
    let bytes = kcrypto_bytes();
    let parsed = parse_kcrypto_object(&bytes).expect("real object must parse");
    // The Task-2 sensor: 9 fexit programs, one per P0 symbol.
    assert_eq!(parsed.programs.len(), 9);
    let mut suffixes: Vec<&str> = Vec::with_capacity(9);
    for prog in &parsed.programs {
        let suffix = prog.section.strip_prefix("fexit/").unwrap_or_else(|| {
            panic!("section must be fexit/*, got {}", prog.section);
        });
        assert!(!prog.name.is_empty(), "program name must be set");
        assert!(!prog.insns.is_empty(), "{} has no insns", prog.name);
        suffixes.push(suffix);
    }
    suffixes.sort_unstable();
    let mut want: Vec<&str> = KCRYPTO_SYMBOLS.to_vec();
    want.sort_unstable();
    assert_eq!(suffixes, want, "fexit sections must cover the 9 P0 symbols");
}

#[test]
fn destroy_exit_does_not_read_released_transform_memory() {
    // The final destroy can free the transform before its fexit program
    // runs. A successful probe read would still not establish a live
    // object. This bytecode regression catches the actual helper-based
    // chase that produced name-read losses on 6.12 (and could read reused
    // storage). Only the skip counter is valid at this boundary.
    let parsed = parse_kcrypto_object(&kcrypto_bytes()).expect("real object must parse");
    let destroy = parsed
        .programs
        .iter()
        .find(|p| p.section == "fexit/crypto_destroy_tfm")
        .expect("destroy boundary remains attached");
    let helpers: Vec<_> = destroy
        .insns
        .iter()
        .filter(|insn| insn.code == 0x85)
        .map(|insn| insn.imm)
        .collect();
    assert!(
        !helpers.is_empty() && helpers.iter().all(|&helper| helper == 1),
        "destroy exit may only look up its skip counter, not probe released memory: {helpers:?}"
    );
    // Positive control: parse the real operation's probe-read helper too,
    // so a parser that erased helper calls cannot satisfy the audit.
    let encrypt = parsed
        .programs
        .iter()
        .find(|p| p.section == "fexit/crypto_skcipher_encrypt")
        .expect("operation boundary remains attached");
    assert!(
        encrypt
            .insns
            .iter()
            .any(|insn| insn.code == 0x85 && insn.imm == 113),
        "positive control must contain bpf_probe_read_kernel"
    );
}

#[test]
fn rejects_garbage_as_kcrypto() {
    assert!(matches!(
        parse_kcrypto_object(b"not an elf file at all...................."),
        Err(LoaderError::BadObject { .. })
    ));
    assert!(matches!(
        parse_kcrypto_object(&[]),
        Err(LoaderError::BadObject { .. })
    ));
}

#[test]
fn rejects_spine_object_as_kcrypto() {
    // Shape mismatch, spine direction: no `fexit/` sections, so the
    // error names the section allowlist.
    let err = parse_kcrypto_object(&spine_bytes()).unwrap_err();
    assert!(
        matches!(err, LoaderError::BadObject { ref reason } if reason.contains("fexit/")),
        "spine-as-kcrypto must name the allowlist, got {err}"
    );
}

#[test]
fn rejects_kcrypto_object_as_spine() {
    // Shape mismatch, kcrypto direction: the spine dims assert fires.
    let err = parse_spine_object(&kcrypto_bytes()).unwrap_err();
    assert!(
        matches!(err, LoaderError::BadObject { .. }),
        "kcrypto-as-spine must be BadObject, got {err}"
    );
}

#[test]
fn rejects_dotted_pin_name() {
    // R3, before any syscall (runs unprivileged).
    for name in ["kcrypto.prog", "KCFG.0"] {
        assert!(
            matches!(check_pin_name(name), Err(LoaderError::BadPinName { .. })),
            "{name} must be BadPinName"
        );
    }
    assert!(check_pin_name("KCFG").is_ok());
}

/// Live BTF available (unprivileged read)? Honest-skip gate for the
/// resolver tests on BTF-less hosts.
fn btf_available() -> bool {
    std::fs::metadata("/sys/kernel/btf/vmlinux").is_ok()
}

#[test]
fn resolve_btf_ids_finds_p0_symbols() {
    if !btf_available() {
        println!("SKIP: no /sys/kernel/btf/vmlinux on this host");
        return;
    }
    let ids = resolve_btf_ids().expect("P0 symbols must resolve");
    assert_eq!(ids.len(), KCRYPTO_SYMBOLS.len());
    // Presence by NAME, never hardcoded ids (ids vary by kernel).
    for name in KCRYPTO_SYMBOLS {
        let id = ids.get(*name).unwrap_or_else(|| panic!("{name} missing"));
        assert!(*id > 0, "{name} id must be nonzero");
    }
}

#[test]
fn resolve_offsets_are_structural() {
    if !btf_available() {
        println!("SKIP: no /sys/kernel/btf/vmlinux on this host");
        return;
    }
    let off = resolve_aggregate_offsets().expect("offsets must resolve");
    // Structural only (exact values are host-coupled; the synthetic
    // unit test in `btf_resolve` pins exactness).
    for (name, value) in [
        ("sk_req_base", off.sk_req_base),
        ("async_tfm", off.async_tfm),
        ("tfm_alg", off.tfm_alg),
        ("alg_name", off.alg_name),
        ("alg_drv", off.alg_drv),
        ("task_flags", off.task_flags),
        ("aead_cryptlen_off", off.aead_cryptlen_off),
        ("ahash_nbytes_off", off.ahash_nbytes_off),
        ("shash_base", off.shash_base),
    ] {
        assert!(value < 4096, "{name}={value} out of range");
    }
    assert!(
        off.alg_drv > off.alg_name,
        "driver name sits past the name: {off:?}"
    );
}

#[test]
fn resolve_lifecycle_offsets_are_structural() {
    // D3: the shape-validated lifecycle set resolves on the live
    // host BTF (structural only — exact values are host-coupled;
    // the synthetic typed fixture pins exactness + refusals).
    if !btf_available() {
        println!("SKIP: no /sys/kernel/btf/vmlinux on this host");
        return;
    }
    let off = resolve_lifecycle_offsets().expect("lifecycle offsets must resolve");
    for (name, value) in [
        ("tfm_alg", off.tfm_alg),
        ("alg_drv", off.alg_drv),
        ("sk_base", off.sk_base),
        ("req_base", off.req_base),
        ("req_tfm", off.req_tfm),
        ("refcnt_off", off.refcnt_off),
    ] {
        assert!(value < 4096, "{name}={value} out of range");
    }
    // Cross-consumer agreement: the lifecycle request link resolves
    // the same members the aggregate identity chain uses.
    let agg = resolve_aggregate_offsets().expect("aggregate offsets must resolve");
    assert_eq!(off.req_base, agg.sk_req_base, "same skcipher_request.base");
    assert_eq!(off.req_tfm, agg.async_tfm, "same async_request.tfm");
    assert_eq!(off.tfm_alg, agg.tfm_alg, "same tfm.__crt_alg");
    assert_eq!(off.alg_drv, agg.alg_drv, "same cra_driver_name");
}

fn is_root() -> bool {
    // SAFETY: idempotent getter.
    unsafe { libc::geteuid() == 0 }
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

fn group(scope: TargetScope) -> LinkGroup {
    let mut alloc = CookieAllocator::new(PlanGeneration::new(1));
    let range = alloc.allocate(1).expect("group range fits");
    // The program label rides the group unchecked on the attach path;
    // kcrypto carries the self-probe label until a dedicated
    // `ProgramId` lands (K2).
    LinkGroup::from_range(
        object(),
        ProgramId::UprobeMultiSelfProbe,
        scope,
        true,
        range,
    )
}

fn guard(generation: u32) -> GenerationGuard {
    GenerationGuard {
        generation: PlanGeneration::new(generation),
    }
}

/// All 9 attach ids, keyed by section suffix (the honest `load_kcrypto`
/// shape: every program binds its own symbol's BTF id).
fn all_attach_ids(ids: &std::collections::HashMap<String, u32>) -> Vec<(String, u32)> {
    KCRYPTO_SYMBOLS
        .iter()
        .map(|name| {
            let id = ids
                .get(*name)
                .unwrap_or_else(|| panic!("{name} missing from resolver output"));
            ((*name).to_owned(), *id)
        })
        .collect()
}

/// Kernel-side fd liveness via fcntl (no bpftool oracle).
fn assert_fcntl_alive(fd: i32, what: &str) {
    // SAFETY: `F_GETFD` only reads flags of an open fd we hold.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0, "{what}: fd {fd} is not alive");
}

/// Procfs fd-kind check: `/proc/self/fd/N` must read as `kind`.
/// (The kernel spells these inconsistently: `bpf_link` with an
/// underscore, `bpf-prog`/`bpf-map` with hyphens — asserted as-is.)
fn assert_procfs_kind(fd: i32, kind: &str, what: &str) {
    let target = std::fs::read_link(format!("/proc/self/fd/{fd}"))
        .unwrap_or_else(|err| panic!("{what}: cannot read fd link {fd}: {err}"));
    assert_eq!(
        target,
        Path::new(kind),
        "{what}: fd {fd} is not a {kind} (got {})",
        target.display()
    );
}

#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn attach_all_points() {
    // SAFETY: idempotent getter.
    if !is_root() {
        println!("SKIP: kcrypto attach matrix requires root (euid != 0)");
        return;
    }
    if !btf_available() {
        println!("SKIP: no /sys/kernel/btf/vmlinux on this host");
        return;
    }
    let bytes = kcrypto_bytes();
    let ids = resolve_btf_ids().expect("P0 symbols must resolve");
    // ONE load of the true 9-prog object with all 9 attach ids; every
    // program binds its own section suffix.
    let (loaded, statuses) = load_kcrypto(&bytes, &all_attach_ids(&ids), None)
        .unwrap_or_else(|err| panic!("9-prog load failed: {err}"));
    assert_eq!(statuses.len(), 9);
    for status in &statuses {
        assert!(
            matches!(status, PointStatus::Loaded { .. }),
            "expected Loaded, got {status:?}"
        );
    }
    assert_eq!(loaded.progs.len(), 9);
    // Attach all 9, in load order (deterministic, not HashMap order).
    let mut links = Vec::new();
    for (name, prog) in &loaded.progs {
        let link = LocalPrivilegedAuthority
            .attach_group(
                &group(TargetScope::System),
                &guard(1),
                prog,
                Path::new(""),
                &[],
            )
            .unwrap_or_else(|err| panic!("attach for {name} failed: {err}"));
        links.push((name.clone(), link));
    }
    assert_eq!(links.len(), 9, "the matrix is 9 points");
    // 9 live links, self-consistent: distinct fds, each fcntl-alive
    // and a kernel bpf-link; plus one prog + one map kind check.
    let mut fds = HashSet::new();
    for (name, link) in &links {
        let fd = link.as_raw_fd();
        assert!(fd >= 0, "{name}: link fd invalid");
        assert!(fds.insert(fd), "duplicate link fd {fd}");
        assert_fcntl_alive(fd, name);
        assert_procfs_kind(fd, "anon_inode:bpf_link", name);
    }
    assert_procfs_kind(
        loaded.progs[0].1.as_raw_fd(),
        "anon_inode:bpf-prog",
        "first kcrypto prog",
    );
    assert_procfs_kind(
        loaded.maps.config.as_raw_fd(),
        "anon_inode:bpf-map",
        "KCFG map",
    );
    // Detach: RAII drop (links first, then progs/maps); assert clean.
    drop(links);
    drop(loaded);
}

/// Our bpffs pin dir (pid-suffixed: never collides, never shared).
fn pin_dir() -> PathBuf {
    PathBuf::from("/sys/fs/bpf").join(format!("k1t1probe-{}", std::process::id()))
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
fn pin_roundtrip_proves_r2_and_cleanup() {
    if !is_root() {
        println!("SKIP: kcrypto pin roundtrip requires root (euid != 0)");
        return;
    }
    if !btf_available() {
        println!("SKIP: no /sys/kernel/btf/vmlinux on this host");
        return;
    }
    let bytes = kcrypto_bytes();
    let ids = resolve_btf_ids().expect("P0 symbols must resolve");
    let (loaded, _) = load_kcrypto(&bytes, &all_attach_ids(&ids), None)
        .unwrap_or_else(|err| panic!("load for pin roundtrip failed: {err}"));
    // Dotted names reject typed even as root (no syscall attempted).
    assert!(
        matches!(
            pin_fd(
                &loaded.maps.config,
                Path::new("/sys/fs/bpf"),
                "kcrypto.prog"
            ),
            Err(LoaderError::BadPinName { .. })
        ),
        "dotted pin must be BadPinName"
    );
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
        // R2: the 20-byte pin attr lands the map; R3: the dot-free name.
        pin_fd(&loaded.maps.config, &dir, "KCFG")
            .unwrap_or_else(|err| panic!("pin KCFG failed: {err}"));
        assert!(dir.join("KCFG").exists(), "pin file must exist after pin");
    } // Guard drops: pin file + dir unlinked on all paths.
    assert!(
        !dir.exists(),
        "pin dir must be gone after cleanup: {}",
        dir.display()
    );
}
