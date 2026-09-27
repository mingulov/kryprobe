// SPDX-License-Identifier: GPL-3.0-or-later
//! T06 H01/H02: lifecycle profile manifest + object gates (RED-first).
//!
//! H01 pins the named-profile contract as pure functions: the
//! `request-lifecycle` manifest (required sites, frozen map table,
//! manifest-derived program limit), per-profile section allowlists
//! (api-returns stays fexit-only — never relaxed), the
//! required-missing refusal gate, zeroed-config fail-closed, and the
//! member-offset/width validators. H02 (below) drives the
//! full-object parse over synthetic ELF fixtures.

use kryprobe_privilege::bpfloader::{LoaderError, MapDims, PointStatus};
use kryprobe_privilege::btf_resolve::{
    BtfError, LifecycleOffsets, resolve_lifecycle_ids, resolve_lifecycle_ids_from,
};

/// Canned chase offsets for LCFG v6 byte tests (values mirror the
/// typed lifecycle fixture: tfm_alg 32, alg_drv 188, sk_base 8,
/// req_base 32, req_tfm 32, req_cryptlen 0, req_flags 40, refcnt 40 +
/// present, aead_req_base 32, aead_req_cryptlen 0, aead_req_assoclen
/// 4, aead_base 8, aead_authsize 0).
fn test_offsets() -> LifecycleOffsets {
    LifecycleOffsets {
        tfm_alg: 32,
        alg_drv: 188,
        sk_base: 8,
        req_base: 32,
        req_tfm: 32,
        req_cryptlen: 0,
        req_flags: 40,
        refcnt_off: 40,
        refcnt_present: true,
        aead_req_base: 32,
        aead_req_cryptlen: 0,
        aead_req_assoclen: 4,
        aead_base: 8,
        aead_authsize: 0,
    }
}
use kryprobe_privilege::kcrypto_lifecycle::profile::{
    ConfigVerifyError, LCFG_VALUE_LEN, LIFECYCLE_MAPS, LifecycleProfile, SessionBusy,
    acquire_kcrypto_session, disarm_config_bytes, lifecycle_config_bytes, manifest, max_programs,
    missing_required_points, parse_lifecycle_object, required_gate_error, section_allowed,
    validate_lifecycle_config, validate_member, verify_lifecycle_config_bytes,
};

#[test]
fn h01_lifecycle_manifest_requires_both_sites() {
    // The T06 profile observes the two T04-qualified api sites (W8:
    // one fsession program per site runs at entry AND return — both
    // edges ride one link; anything less cannot observe both ops).
    // T07.2 adds the skcipher allocation site (generation assignment
    // needs alloc entry/return capture). T07.3 adds the destroy site
    // (retire needs destroy entry/return capture). T07.4 adds the
    // three configuration sites (epochs need setkey/setauthsize
    // entry/return capture). P5 adds the AEAD op sites plus the AEAD
    // allocation site (the AEAD lifetime observations the
    // config-only support must not masquerade as).
    let m = manifest(LifecycleProfile::RequestLifecycle);
    assert_eq!(m.name, "request-lifecycle");
    let sites: Vec<&str> = m.required.iter().map(|s| s.symbol).collect();
    assert_eq!(
        sites,
        [
            "crypto_skcipher_encrypt",
            "crypto_skcipher_decrypt",
            "crypto_alloc_skcipher",
            "crypto_destroy_tfm",
            "crypto_skcipher_setkey",
            "crypto_aead_setauthsize",
            "crypto_aead_setkey",
            "crypto_aead_encrypt",
            "crypto_aead_decrypt",
            "crypto_alloc_aead"
        ]
    );
}

#[test]
fn h01_program_limit_derives_from_manifest_not_global_cap() {
    // One fsession program per required site (10) plus one fentry
    // program per callback site (2) = 12; the api-returns 16-program
    // cap is a different profile's limit and must not leak across.
    let lc = manifest(LifecycleProfile::RequestLifecycle);
    assert_eq!(max_programs(&lc), 12);
    let api = manifest(LifecycleProfile::ApiReturns);
    assert_eq!(max_programs(&api), 16);
    assert_ne!(max_programs(&lc), max_programs(&api));
}

#[test]
fn h01_lifecycle_sections_accept_pinned_set() {
    // W8: lifecycle objects carry `fsession/` programs; P4 adds the
    // two EXACT `fentry/` callback sections (no open prefix — any
    // other fentry/fexit object refuses here, fail-closed).
    let p = LifecycleProfile::RequestLifecycle;
    assert!(section_allowed(p, "fsession/crypto_skcipher_encrypt"));
    assert!(section_allowed(p, "fsession/crypto_skcipher_decrypt"));
    assert!(section_allowed(p, "fsession/crypto_aead_encrypt"));
    assert!(section_allowed(p, "fsession/crypto_aead_decrypt"));
    assert!(section_allowed(p, "fsession/crypto_alloc_aead"));
    assert!(section_allowed(p, "fentry/cryptd_skcipher_complete"));
    assert!(section_allowed(p, "fentry/kxc_complete"));
    assert!(!section_allowed(p, "fentry/crypto_skcipher_encrypt"));
    assert!(!section_allowed(p, "fexit/crypto_skcipher_encrypt"));
    assert!(!section_allowed(p, "fentry/crypto_skcipher_decrypt"));
    assert!(!section_allowed(p, "fexit/crypto_skcipher_decrypt"));
    assert!(!section_allowed(p, "fentry/crypto_request_complete"));
    assert!(!section_allowed(p, "fentry/complete"));
    assert!(!section_allowed(p, "fsession/"));
    assert!(!section_allowed(p, "fsession"));
    assert!(!section_allowed(p, "kprobe/crypto_skcipher_encrypt"));
    assert!(!section_allowed(p, "uprobe.multi"));
    assert!(!section_allowed(p, ""));
}

#[test]
fn h01_api_returns_sections_stay_fexit_only() {
    // C1 ruling frozen: adding a lifecycle profile must not relax the
    // api-returns fexit-only shape (plan: "never merely relax").
    let p = LifecycleProfile::ApiReturns;
    assert!(section_allowed(p, "fexit/crypto_alloc_tfm_node"));
    assert!(section_allowed(p, "fexit/x"));
    assert!(!section_allowed(p, "fentry/crypto_alloc_tfm_node"));
    assert!(!section_allowed(p, "fentry/x"));
    assert!(!section_allowed(p, "fsession/x"));
    assert!(!section_allowed(p, "uprobe.multi"));
    assert!(!section_allowed(p, "fexit"));
    assert!(!section_allowed(p, ""));
}

#[test]
fn h01_lifecycle_map_table_is_exact_and_dot_free() {
    // LCFG (config), LRING (edge ringbuf), LLOSS (per-CPU loss,
    // 5 classes x 18 hook lanes), LAGG (per-CPU accepted aggregate,
    // 18 lanes), LCTR (per-CPU per-program mint sequence, 8 lanes —
    // callbacks don't mint): the W8 T06 contract grown to the
    // T07-final counter shape, P4-grown to 18 lanes, which the BPF
    // object must match byte-for-byte (pairing state is
    // kernel-owned — no slot, quarantine, or overflow tables).
    assert_eq!(LIFECYCLE_MAPS.len(), 5);
    let names: Vec<&str> = LIFECYCLE_MAPS.iter().map(|(n, _)| *n).collect();
    assert_eq!(names, ["LCFG", "LRING", "LLOSS", "LAGG", "LCTR"]);
    for name in &names {
        assert!(!name.contains('.'), "R3 dot-free gate: {name}");
    }
    let dims = |n: &str| {
        LIFECYCLE_MAPS
            .iter()
            .find(|(m, _)| *m == n)
            .map(|(_, d)| *d)
            .expect("table names match")
    };
    assert_eq!(
        dims("LCFG"),
        MapDims {
            map_type: 2,
            key_size: 4,
            value_size: 80,
            max_entries: 1,
        }
    );
    assert_eq!(
        dims("LRING"),
        MapDims {
            map_type: 27,
            key_size: 0,
            value_size: 0,
            max_entries: 262_144,
        }
    );
    assert_eq!(
        dims("LLOSS"),
        MapDims {
            map_type: 6,
            key_size: 4,
            value_size: 8,
            max_entries: 110,
        }
    );
    assert_eq!(
        dims("LAGG"),
        MapDims {
            map_type: 6,
            key_size: 4,
            value_size: 8,
            max_entries: 22,
        }
    );
    assert_eq!(
        dims("LCTR"),
        MapDims {
            map_type: 6,
            key_size: 4,
            value_size: 8,
            max_entries: 10,
        }
    );
}

#[test]
fn h01_zeroed_config_fails_closed() {
    // All-zero LCFG (unwritten map read-back) never arms the sensor;
    // only the exact magic+version arms it (P4: version 5 — older
    // bytes disarm, versions never mix).
    assert!(validate_lifecycle_config(0, 0, 0).is_err());
    assert!(validate_lifecycle_config(0x31434c4b, 0, 0).is_err());
    assert!(validate_lifecycle_config(0, 5, 0).is_err());
    assert!(validate_lifecycle_config(0x31434c4b, 1, 0).is_err());
    assert!(validate_lifecycle_config(0x31434c4b, 2, 0).is_err());
    assert!(validate_lifecycle_config(0x31434c4b, 3, 0).is_err());
    assert!(validate_lifecycle_config(0x31434c4b, 4, 0).is_err());
    assert!(validate_lifecycle_config(0x31434c4b, 6, 0).is_ok());
}

#[test]
fn f1_lcfg_readback_validates_full_80_bytes() {
    // Round-1 finding (sol-M1/astra-M1): the verify path read the
    // LCFG value into an 8-byte u64 (72-byte stack overwrite at the
    // v6 80-byte width). The read-back verifier takes the full 80
    // bytes: short reads fail closed, and every word
    // (magic/version/flags/tail) must match. T07: the tail verifies
    // against the WRITTEN bytes (offset words ride there now —
    // shape-only would certify a mis-chaser).
    use kryprobe_privilege::btf_resolve::LifecycleOffsets;
    let off = LifecycleOffsets {
        tfm_alg: 32,
        alg_drv: 188,
        sk_base: 8,
        req_base: 0,
        req_tfm: 0,
        req_cryptlen: 0,
        req_flags: 0,
        refcnt_off: 0,
        refcnt_present: false,
        aead_req_base: 0,
        aead_req_cryptlen: 0,
        aead_req_assoclen: 0,
        aead_base: 0,
        aead_authsize: 0,
    };
    let good = lifecycle_config_bytes(&off, 16, true);
    assert_eq!(good.len(), 80);
    // P4 v5: the fixture op words ride at 48/52 (offset 16 here is
    // the test's arbitrary value — the live arm BTF-resolves it).
    assert_eq!(u32::from_le_bytes(good[48..52].try_into().unwrap()), 16);
    assert_eq!(u32::from_le_bytes(good[52..56].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(good[4..8].try_into().unwrap()), 6);
    assert!(verify_lifecycle_config_bytes(&good, &good).is_ok());
    assert!(matches!(
        verify_lifecycle_config_bytes(&good[..8], &good),
        Err(ConfigVerifyError::BadLength { got: 8 })
    ));
    assert!(matches!(
        verify_lifecycle_config_bytes(&[0u8; 80], &good),
        Err(ConfigVerifyError::BadMagic)
    ));
    let mut bad_version = good;
    bad_version[4] = 0x7f;
    assert!(matches!(
        verify_lifecycle_config_bytes(&bad_version, &good),
        Err(ConfigVerifyError::BadVersion)
    ));
    let mut bad_flags = good;
    bad_flags[8] = 1;
    // (Byte 8 = 1 is exactly the disarmed shape — the ARM verifier
    // rightly refuses it; arming a disarmed value is never valid.)
    assert!(matches!(
        verify_lifecycle_config_bytes(&bad_flags, &good),
        Err(ConfigVerifyError::BadFlags)
    ));
    let mut bad_reserved = good;
    bad_reserved[79] = 1;
    assert!(matches!(
        verify_lifecycle_config_bytes(&bad_reserved, &good),
        Err(ConfigVerifyError::BadReserved { offset: 79 })
    ));
}

#[test]
fn t07_lcfg_disarm_flips_flags_word_only() {
    // D1: the disarm preserves magic/version/offsets/tail
    // bit-for-bit and sets ONLY the flags word to LCONFIG_DISABLED
    // — a hook racing the disarm never mixes valid offsets with
    // zeroed words. From armed bytes (flags 0) the delta is exactly
    // one byte (byte 8: 0 -> 1), which cannot tear under concurrent
    // aligned-word readers.
    use kryprobe_abi::kcrypto_lifecycle::LCONFIG_DISABLED;
    use kryprobe_privilege::btf_resolve::LifecycleOffsets;
    let off = LifecycleOffsets {
        tfm_alg: 32,
        alg_drv: 188,
        sk_base: 8,
        req_base: 0,
        req_tfm: 0,
        req_cryptlen: 0,
        req_flags: 0,
        refcnt_off: 0,
        refcnt_present: false,
        aead_req_base: 0,
        aead_req_cryptlen: 0,
        aead_req_assoclen: 0,
        aead_base: 0,
        aead_authsize: 0,
    };
    let armed = lifecycle_config_bytes(&off, 16, true);
    let disarmed = disarm_config_bytes(&armed);
    let diffs: Vec<usize> = (0..LCFG_VALUE_LEN)
        .filter(|&i| armed[i] != disarmed[i])
        .collect();
    assert_eq!(diffs, vec![8], "single-byte delta at byte 8");
    assert_eq!(
        u32::from_le_bytes([disarmed[8], disarmed[9], disarmed[10], disarmed[11]]),
        LCONFIG_DISABLED,
        "flags word carries DISABLED"
    );
    assert_eq!(&armed[..8], &disarmed[..8], "magic+version intact");
    assert_eq!(&armed[12..], &disarmed[12..], "offsets+tail intact");
    // Idempotent (a second disarm pass changes nothing) and safe on
    // an unwritten map (flags-only: gate still closed on magic).
    assert_eq!(disarm_config_bytes(&disarmed), disarmed, "idempotent");
    let zero_disarmed = disarm_config_bytes(&[0u8; LCFG_VALUE_LEN]);
    assert_eq!(
        u32::from_le_bytes([
            zero_disarmed[8],
            zero_disarmed[9],
            zero_disarmed[10],
            zero_disarmed[11]
        ]),
        LCONFIG_DISABLED,
        "zero map disarms to flags-only"
    );
    assert!(zero_disarmed[..8].iter().all(|b| *b == 0));
    assert!(zero_disarmed[12..].iter().all(|b| *b == 0));
    // The disarmed shape fails the ARM verifier (flags nonzero) —
    // disarming never produces an armable value.
    assert!(matches!(
        verify_lifecycle_config_bytes(&disarmed, &armed),
        Err(ConfigVerifyError::BadFlags)
    ));
}

#[test]
fn t07_lcfg_v3_carries_chase_offsets() {
    // T07.3: the arm writes the BTF-resolved chase offsets into the
    // config words (version 6: chase + refcount + request-link +
    // request-metadata + fixture-op + AEAD words); the reserved tail
    // stays zero.
    use kryprobe_privilege::btf_resolve::LifecycleOffsets;
    let off = LifecycleOffsets {
        tfm_alg: 32,
        alg_drv: 188,
        sk_base: 8,
        req_base: 48,
        req_tfm: 52,
        req_cryptlen: 0,
        req_flags: 40,
        refcnt_off: 40,
        refcnt_present: true,
        aead_req_base: 56,
        aead_req_cryptlen: 60,
        aead_req_assoclen: 64,
        aead_base: 68,
        aead_authsize: 72,
    };
    let bytes = lifecycle_config_bytes(&off, 0, false);
    assert_eq!(bytes.len(), 80);
    let word = |i: usize| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
    assert_eq!(word(0), 0x31434c4b, "magic");
    assert_eq!(word(4), 6, "version 6");
    assert_eq!(word(8), 0, "flags");
    assert_eq!(word(12), 32, "tfm_alg");
    assert_eq!(word(16), 188, "alg_drv");
    assert_eq!(word(20), 8, "sk_base");
    assert_eq!(word(24), 40, "refcnt_off");
    assert_eq!(word(28), 1, "refcnt_present");
    assert_eq!(word(32), 48, "req_base");
    assert_eq!(word(36), 52, "req_tfm");
    assert_eq!(word(40), 0, "req_cryptlen");
    assert_eq!(word(44), 40, "req_flags");
    assert_eq!(word(56), 56, "aead_req_base");
    assert_eq!(word(60), 60, "aead_req_cryptlen");
    assert_eq!(word(64), 64, "aead_req_assoclen");
    assert_eq!(word(68), 68, "aead_base");
    assert_eq!(word(72), 72, "aead_authsize");
    assert!(bytes[76..].iter().all(|b| *b == 0), "reserved tail zero");
}

#[test]
fn t07_lcfg_verify_checks_tail_against_written() {
    // T07: the read-back must equal the written bytes in full — a
    // corrupted offset word would mis-chase in BPF, so shape-only
    // verification no longer suffices.
    use kryprobe_privilege::btf_resolve::LifecycleOffsets;
    let off = LifecycleOffsets {
        tfm_alg: 32,
        alg_drv: 188,
        sk_base: 8,
        req_base: 0,
        req_tfm: 0,
        req_cryptlen: 0,
        req_flags: 0,
        refcnt_off: 0,
        refcnt_present: false,
        aead_req_base: 0,
        aead_req_cryptlen: 0,
        aead_req_assoclen: 0,
        aead_base: 0,
        aead_authsize: 0,
    };
    let good = lifecycle_config_bytes(&off, 16, true);
    assert!(verify_lifecycle_config_bytes(&good, &good).is_ok());
    let mut bad_off = good;
    bad_off[12] ^= 0xff;
    assert!(matches!(
        verify_lifecycle_config_bytes(&bad_off, &good),
        Err(ConfigVerifyError::BadReserved { offset: 12 })
    ));
    let mut bad_tail = good;
    bad_tail[79] = 1;
    assert!(matches!(
        verify_lifecycle_config_bytes(&bad_tail, &good),
        Err(ConfigVerifyError::BadReserved { offset: 79 })
    ));
}

#[test]
fn f10_required_gate_preserves_load_error_type() {
    // Round-1 (sol-m10/astra-m10): a required point's load refusal
    // must surface typed (errno + verifier tail), not as a
    // shape-flavored BadObject. Shape-only misses stay BadObject.
    let missing = vec!["fsession/crypto_skcipher_encrypt".to_owned()];
    let load_errors = vec![(
        "fsession/crypto_skcipher_encrypt".to_owned(),
        LoaderError::LoadFailed {
            stage: "kcrypto_encrypt_session".to_owned(),
            errno: 13,
            log: "verifier tail".to_owned(),
        },
    )];
    match required_gate_error(&missing, &load_errors) {
        LoaderError::LoadFailed { stage, errno, log } => {
            assert_eq!(errno, 13);
            assert_eq!(log, "verifier tail");
            assert!(
                stage.contains("fsession/crypto_skcipher_encrypt"),
                "{stage}"
            );
        }
        other => panic!("want LoadFailed, got {other:?}"),
    }
    match required_gate_error(&missing, &[]) {
        LoaderError::BadObject { reason } => {
            assert!(
                reason.contains("fsession/crypto_skcipher_encrypt"),
                "{reason}"
            );
        }
        other => panic!("want BadObject, got {other:?}"),
    }
}

#[test]
fn f1_lcfg_value_len_matches_manifest() {
    // The read-back buffer size is only sound when it equals the
    // manifest width the loader instantiates; drift here reopens
    // the round-1 stack overwrite, so the equality is pinned.
    let (_, dims) = LIFECYCLE_MAPS
        .iter()
        .find(|(name, _)| *name == "LCFG")
        .expect("LCFG in manifest");
    assert_eq!(dims.value_size as usize, LCFG_VALUE_LEN);
    assert_eq!(
        lifecycle_config_bytes(&test_offsets(), 16, true).len(),
        LCFG_VALUE_LEN
    );
}

#[test]
fn h01_member_validator_bounds_widths_and_overflow() {
    // (struct_size, offset, width): in-bounds scalars pass; zero width,
    // non-power widths, overruns and offset+width overflow refuse.
    assert!(validate_member(64, 0, 8).is_ok());
    assert!(validate_member(64, 56, 8).is_ok());
    assert!(validate_member(64, 0, 1).is_ok());
    assert!(validate_member(64, 0, 2).is_ok());
    assert!(validate_member(64, 0, 4).is_ok());
    assert!(validate_member(64, 0, 0).is_err());
    assert!(validate_member(64, 0, 3).is_err());
    assert!(validate_member(64, 0, 16).is_err());
    assert!(validate_member(64, 57, 8).is_err());
    assert!(validate_member(64, 64, 1).is_err());
    assert!(validate_member(64, u32::MAX, 8).is_err());
    assert!(validate_member(u32::MAX, u32::MAX - 3, 8).is_err());
}

// ---------------------------------------------------------------------------
// H02: synthetic lifecycle objects (minimal ELF64, no BPF toolchain).
// ---------------------------------------------------------------------------

/// Minimal relocatable ELF64 with `license` + `maps` + program sections.
///
/// Program sections carry one `exit` insn, `SHF_EXECINSTR`, and a
/// `STT_FUNC` symbol; maps carry 28-byte legacy defs plus `STT_NOTYPE`
/// symbols. Enough for the loader's parse path, nothing more.
fn build_lifecycle_fixture(prog_sections: &[&str], maps: &[(&str, MapDims)]) -> Vec<u8> {
    const EM_BPF: u16 = 247;
    const SHF_EXEC: u64 = 0x6;
    const STT_NOTYPE: u8 = 0;
    const STT_FUNC: u8 = 2;
    // Section contents in emission order (index 0 is the NULL section).
    let mut contents: Vec<Vec<u8>> = vec![Vec::new()];
    contents.push(b"GPL\0".to_vec());
    let mut maps_bytes = Vec::new();
    for (_, dims) in maps {
        maps_bytes.extend_from_slice(&dims.map_type.to_le_bytes());
        maps_bytes.extend_from_slice(&dims.key_size.to_le_bytes());
        maps_bytes.extend_from_slice(&dims.value_size.to_le_bytes());
        maps_bytes.extend_from_slice(&dims.max_entries.to_le_bytes());
        maps_bytes.extend_from_slice(&[0u8; 12]);
    }
    contents.push(maps_bytes);
    // bpf-linker NULL stub: unnamed, NULL-typed, AX-flagged (real
    // objects carry it as section [2]; the parse must skip it).
    contents.push(vec![0u8; 8]);
    for _ in prog_sections {
        contents.push(vec![0x95, 0, 0, 0, 0, 0, 0, 0]);
    }
    let mut names = vec![
        "".to_owned(),
        "license".to_owned(),
        "maps".to_owned(),
        "".to_owned(),
    ];
    names.extend(prog_sections.iter().map(|s| (*s).to_owned()));
    names.extend([
        "symtab".to_owned(),
        "strtab".to_owned(),
        "shstrtab".to_owned(),
    ]);
    // String tables.
    let mut strtab = vec![0u8];
    let str_off = |s: &str, tab: &mut Vec<u8>| -> u32 {
        let off = tab.len() as u32;
        tab.extend_from_slice(s.as_bytes());
        tab.push(0);
        off
    };
    let mut sym_names = Vec::new();
    for (name, _) in maps {
        sym_names.push(str_off(name, &mut strtab));
    }
    for sec in prog_sections {
        let func = sec.rsplit('/').next().unwrap_or("prog");
        sym_names.push(str_off(func, &mut strtab));
    }
    let mut shstrtab = vec![0u8];
    let mut name_offs = Vec::new();
    for name in &names {
        name_offs.push(str_off(name, &mut shstrtab));
    }
    // Symbols: map NOTYPEs then program FUNCs.
    let mut symtab = Vec::new();
    let mut emit_sym = |st_name: u32, info: u8, shndx: u16, value: u64| {
        symtab.extend_from_slice(&st_name.to_le_bytes());
        symtab.push(info);
        symtab.push(0);
        symtab.extend_from_slice(&shndx.to_le_bytes());
        symtab.extend_from_slice(&value.to_le_bytes());
        symtab.extend_from_slice(&0u64.to_le_bytes());
    };
    emit_sym(0, 0, 0, 0);
    for (i, off) in sym_names.iter().enumerate() {
        if i < maps.len() {
            emit_sym(*off, STT_NOTYPE, 2, (i * 28) as u64);
        } else {
            emit_sym(*off, STT_FUNC, (4 + (i - maps.len())) as u16, 0);
        }
    }
    contents.push(symtab);
    contents.push(strtab);
    contents.push(shstrtab);
    // Layout: ehdr @0, contents, then shdrs.
    let mut out = vec![0u8; 64];
    out[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    out[4] = 2;
    out[5] = 1;
    out[6] = 1;
    out[16..18].copy_from_slice(&1u16.to_le_bytes());
    out[18..20].copy_from_slice(&EM_BPF.to_le_bytes());
    let mut sh_off = 64usize;
    let mut sec_file_off = Vec::new();
    for content in &contents {
        if content.is_empty() {
            sec_file_off.push(0);
            continue;
        }
        sec_file_off.push(sh_off);
        sh_off += content.len();
    }
    let shdr_off = sh_off;
    let nsec = contents.len();
    for (i, content) in contents.iter().enumerate() {
        if content.is_empty() {
            continue;
        }
        out.resize(sec_file_off[i] + content.len(), 0);
        out[sec_file_off[i]..sec_file_off[i] + content.len()].copy_from_slice(content);
    }
    out.resize(shdr_off + nsec * 64, 0);
    for i in 0..nsec {
        let base = shdr_off + i * 64;
        let (sh_type, flags, link, info, entsize) = if i == 0 {
            (0u32, 0u64, 0u32, 0u32, 0u64)
        } else if i == 3 {
            (0u32, SHF_EXEC, 0u32, 0u32, 0u64)
        } else if names[i] == "symtab" {
            (
                2u32,
                0u64,
                (nsec - 2) as u32,
                (sym_names.len() + 1) as u32,
                24u64,
            )
        } else if names[i] == "strtab" || names[i] == "shstrtab" {
            (3u32, 0u64, 0u32, 0u32, 0u64)
        } else if names[i] == "license" || names[i] == "maps" {
            (1u32, 0u64, 0u32, 0u32, 0u64)
        } else {
            (1u32, SHF_EXEC, 0u32, 0u32, 0u64)
        };
        out[base..base + 4].copy_from_slice(&name_offs[i].to_le_bytes());
        out[base + 4..base + 8].copy_from_slice(&sh_type.to_le_bytes());
        out[base + 8..base + 16].copy_from_slice(&flags.to_le_bytes());
        out[base + 24..base + 32].copy_from_slice(&(sec_file_off[i] as u64).to_le_bytes());
        out[base + 32..base + 40].copy_from_slice(&(contents[i].len() as u64).to_le_bytes());
        out[base + 40..base + 44].copy_from_slice(&link.to_le_bytes());
        out[base + 44..base + 48].copy_from_slice(&info.to_le_bytes());
        out[base + 56..base + 64].copy_from_slice(&entsize.to_le_bytes());
    }
    out[40..48].copy_from_slice(&(shdr_off as u64).to_le_bytes());
    out[58..60].copy_from_slice(&64u16.to_le_bytes());
    out[60..62].copy_from_slice(&(nsec as u16).to_le_bytes());
    out[62..64].copy_from_slice(&((nsec - 1) as u16).to_le_bytes());
    out
}

/// The P5 contract as a fixture: one fsession program per required
/// site plus the exact frozen map table.
fn valid_lifecycle_fixture() -> Vec<u8> {
    let maps: Vec<(&str, MapDims)> = LIFECYCLE_MAPS.to_vec();
    build_lifecycle_fixture(
        &[
            "fsession/crypto_skcipher_encrypt",
            "fsession/crypto_skcipher_decrypt",
            "fsession/crypto_alloc_skcipher",
            "fsession/crypto_destroy_tfm",
            "fsession/crypto_skcipher_setkey",
            "fsession/crypto_aead_setauthsize",
            "fsession/crypto_aead_setkey",
            "fsession/crypto_aead_encrypt",
            "fsession/crypto_aead_decrypt",
            "fsession/crypto_alloc_aead",
        ],
        &maps,
    )
}

#[test]
fn h02_valid_session_object_parses() {
    let bytes = valid_lifecycle_fixture();
    let parsed = parse_lifecycle_object(&bytes).expect("valid fixture must parse");
    assert_eq!(parsed.maps.len(), 5);
    assert_eq!(parsed.programs.len(), 10);
    for prog in &parsed.programs {
        assert_eq!(prog.insns.len(), 1, "{} stream drifted", prog.name);
    }
    assert!(parsed.map_relocs.is_empty());
}

#[test]
fn h02_missing_required_site_refused_by_name() {
    let maps: Vec<(&str, MapDims)> = LIFECYCLE_MAPS.to_vec();
    let bytes = build_lifecycle_fixture(&["fsession/crypto_skcipher_encrypt"], &maps);
    let err = parse_lifecycle_object(&bytes).expect_err("missing fsession/decrypt must refuse");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("crypto_skcipher_decrypt"),
        "refusal names the site: {msg}"
    );
}

#[test]
fn h02_pre_destroy_object_refused_by_name() {
    // T07.3: the 3-program T07.2 shape (no destroy site) no longer
    // satisfies the manifest — the refusal names the missing site
    // (no silent partial bring-up off a stale object).
    let maps: Vec<(&str, MapDims)> = LIFECYCLE_MAPS.to_vec();
    let bytes = build_lifecycle_fixture(
        &[
            "fsession/crypto_skcipher_encrypt",
            "fsession/crypto_skcipher_decrypt",
            "fsession/crypto_alloc_skcipher",
        ],
        &maps,
    );
    let err = parse_lifecycle_object(&bytes).expect_err("missing destroy must refuse");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("crypto_destroy_tfm"),
        "refusal names the site: {msg}"
    );
}

#[test]
fn h02_pre_config_object_refused_by_name() {
    // T07.4: the 4-program T07.3 shape (no configuration sites) no
    // longer satisfies the manifest — the refusal names the first
    // missing site (no silent partial bring-up off a stale object).
    let maps: Vec<(&str, MapDims)> = LIFECYCLE_MAPS.to_vec();
    let bytes = build_lifecycle_fixture(
        &[
            "fsession/crypto_skcipher_encrypt",
            "fsession/crypto_skcipher_decrypt",
            "fsession/crypto_alloc_skcipher",
            "fsession/crypto_destroy_tfm",
        ],
        &maps,
    );
    let err = parse_lifecycle_object(&bytes).expect_err("missing setkey must refuse");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("crypto_skcipher_setkey"),
        "refusal names the site: {msg}"
    );
}

#[test]
fn h02_wrong_attach_prototype_refused() {
    let maps: Vec<(&str, MapDims)> = LIFECYCLE_MAPS.to_vec();
    let bytes = build_lifecycle_fixture(
        &[
            "fsession/crypto_skcipher_encrypt",
            "kprobe/crypto_skcipher_decrypt",
        ],
        &maps,
    );
    let err = parse_lifecycle_object(&bytes).expect_err("kprobe section must refuse");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("kprobe/crypto_skcipher_decrypt"),
        "refusal names the section: {msg}"
    );
}

#[test]
fn h02_extra_map_refused() {
    let mut maps: Vec<(&str, MapDims)> = LIFECYCLE_MAPS.to_vec();
    maps.push((
        "ZZZ",
        MapDims {
            map_type: 2,
            key_size: 4,
            value_size: 8,
            max_entries: 1,
        },
    ));
    let bytes = build_lifecycle_fixture(
        &[
            "fsession/crypto_skcipher_encrypt",
            "fsession/crypto_skcipher_decrypt",
            "fsession/crypto_alloc_skcipher",
            "fsession/crypto_destroy_tfm",
            "fsession/crypto_skcipher_setkey",
            "fsession/crypto_aead_setauthsize",
            "fsession/crypto_aead_setkey",
            "fsession/crypto_aead_encrypt",
            "fsession/crypto_aead_decrypt",
            "fsession/crypto_alloc_aead",
        ],
        &maps,
    );
    assert!(matches!(
        parse_lifecycle_object(&bytes),
        Err(LoaderError::UnsupportedMap { .. })
    ));
}

#[test]
fn h02_duplicate_map_refused_typed() {
    // Round-6 minor: a map symbol defined twice refuses typed
    // (`DuplicateMap`) — even when both defs carry identical dims
    // (taking the first would bless whichever the symbol order
    // happened to surface). The gate lives in the shared collector,
    // so spine + kcrypto paths inherit it.
    let mut maps: Vec<(&str, MapDims)> = LIFECYCLE_MAPS.to_vec();
    maps.push(maps[0]);
    let bytes = build_lifecycle_fixture(
        &[
            "fsession/crypto_skcipher_encrypt",
            "fsession/crypto_skcipher_decrypt",
            "fsession/crypto_alloc_skcipher",
            "fsession/crypto_destroy_tfm",
            "fsession/crypto_skcipher_setkey",
            "fsession/crypto_aead_setauthsize",
            "fsession/crypto_aead_setkey",
            "fsession/crypto_aead_encrypt",
            "fsession/crypto_aead_decrypt",
            "fsession/crypto_alloc_aead",
        ],
        &maps,
    );
    let err = parse_lifecycle_object(&bytes).expect_err("duplicate LCFG must refuse");
    assert!(
        matches!(err, LoaderError::DuplicateMap { ref name } if name == "LCFG"),
        "typed refusal names the map: {err:?}"
    );
    assert!(
        format!("{err}").contains("LCFG"),
        "Display names the map: {err}"
    );
}

#[test]
fn h02_bad_dims_refused() {
    let mut maps: Vec<(&str, MapDims)> = LIFECYCLE_MAPS.to_vec();
    maps[0].1.value_size = 128;
    let bytes = build_lifecycle_fixture(
        &[
            "fsession/crypto_skcipher_encrypt",
            "fsession/crypto_skcipher_decrypt",
            "fsession/crypto_alloc_skcipher",
            "fsession/crypto_destroy_tfm",
            "fsession/crypto_skcipher_setkey",
            "fsession/crypto_aead_setauthsize",
            "fsession/crypto_aead_setkey",
            "fsession/crypto_aead_encrypt",
            "fsession/crypto_aead_decrypt",
            "fsession/crypto_alloc_aead",
        ],
        &maps,
    );
    assert!(matches!(
        parse_lifecycle_object(&bytes),
        Err(LoaderError::DimMismatch { .. })
    ));
}

#[test]
fn h02_missing_map_refused() {
    let maps: Vec<(&str, MapDims)> = LIFECYCLE_MAPS[..2].to_vec();
    let bytes = build_lifecycle_fixture(
        &[
            "fsession/crypto_skcipher_encrypt",
            "fsession/crypto_skcipher_decrypt",
            "fsession/crypto_alloc_skcipher",
            "fsession/crypto_destroy_tfm",
            "fsession/crypto_skcipher_setkey",
            "fsession/crypto_aead_setauthsize",
            "fsession/crypto_aead_setkey",
            "fsession/crypto_aead_encrypt",
            "fsession/crypto_aead_decrypt",
            "fsession/crypto_alloc_aead",
        ],
        &maps,
    );
    let err = parse_lifecycle_object(&bytes).expect_err("missing LLOSS must refuse");
    assert!(format!("{err:?}").contains("LLOSS"));
}

#[test]
fn h02_too_many_programs_refused_at_manifest_limit() {
    let maps: Vec<(&str, MapDims)> = LIFECYCLE_MAPS.to_vec();
    let bytes = build_lifecycle_fixture(
        &[
            "fsession/crypto_skcipher_encrypt",
            "fsession/crypto_skcipher_decrypt",
            "fsession/crypto_alloc_skcipher",
            "fsession/crypto_destroy_tfm",
            "fsession/crypto_skcipher_setkey",
            "fsession/crypto_aead_setauthsize",
            "fsession/crypto_aead_setkey",
            "fsession/crypto_aead_encrypt",
            "fsession/crypto_aead_decrypt",
            "fsession/crypto_alloc_aead",
            "fentry/cryptd_skcipher_complete",
            "fentry/kxc_complete",
            "fsession/crypto_skcipher_extra",
        ],
        &maps,
    );
    let err = parse_lifecycle_object(&bytes).expect_err("13th program must refuse");
    let msg = format!("{err:?}");
    assert!(msg.contains("12"), "refusal names the manifest limit: {msg}");
}

/// Workspace-relative path of the built lifecycle object.
fn lifecycle_object_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("kryprobe-bpf")
        .join("kcrypto-lifecycle.bpf.o")
}

#[test]
fn h02_built_object_matches_manifest() {
    // Backstop: the real BPF twin must parse under the profile gates
    // with exactly the manifest's sections and map table.
    let path = lifecycle_object_path();
    assert!(
        path.is_file(),
        "missing BPF lifecycle object at {} — run `cargo xtask build --bpf`",
        path.display()
    );
    let bytes = std::fs::read(&path).expect("test fixture must be readable");
    let parsed = parse_lifecycle_object(&bytes).expect("built object must parse");
    let m = manifest(LifecycleProfile::RequestLifecycle);
    assert_eq!(parsed.programs.len(), max_programs(&m));
    let mut sections: Vec<&str> = parsed.programs.iter().map(|p| p.section.as_str()).collect();
    sections.sort_unstable();
    assert_eq!(
        sections,
        [
            "fentry/cryptd_skcipher_complete",
            "fentry/kxc_complete",
            "fsession/crypto_aead_decrypt",
            "fsession/crypto_aead_encrypt",
            "fsession/crypto_aead_setauthsize",
            "fsession/crypto_aead_setkey",
            "fsession/crypto_alloc_aead",
            "fsession/crypto_alloc_skcipher",
            "fsession/crypto_destroy_tfm",
            "fsession/crypto_skcipher_decrypt",
            "fsession/crypto_skcipher_encrypt",
            "fsession/crypto_skcipher_setkey",
        ]
    );
    assert_eq!(parsed.maps.len(), LIFECYCLE_MAPS.len());
    for ((want_name, want_dims), got) in LIFECYCLE_MAPS.iter().zip(parsed.maps.iter()) {
        assert_eq!(got.name, *want_name);
        assert_eq!(got.dims, *want_dims, "dims drifted for {want_name}");
    }
    assert!(
        !parsed.map_relocs.is_empty(),
        "built object must reference its maps"
    );
    for reloc in &parsed.map_relocs {
        assert!(
            parsed.maps.iter().any(|m| m.name == reloc.map),
            "reloc names unknown map {}",
            reloc.map
        );
    }
    for prog in &parsed.programs {
        assert!(!prog.insns.is_empty(), "{} has no insns", prog.name);
    }
}

#[test]
fn w8_built_object_codegen_pins_kfunc_stubs() {
    // Ratification B (implementer proof): the fsession BPF calls the
    // session kfuncs through sentinel immediates with NO relocations
    // (R4-safe by construction — aya has no kfunc support, so the
    // loader rewrites plain `call imm` sites). Pins: zero
    // `R_BPF_64_32` anywhere in the object (map refs ride 64_64), and
    // per program exactly one `is_return` site (0x5F4B0001, the top
    // branch) plus two `cookie` sites (0x5F4B0002, one per run).
    // Every OTHER call imm is a small helper id — no other
    // sentinel-shaped (unrewritable) call target exists.
    const OP_CALL: u8 = 0x85;
    const IS_RETURN: i32 = 0x5F4B_0001;
    const COOKIE: i32 = 0x5F4B_0002;
    let path = lifecycle_object_path();
    assert!(
        path.is_file(),
        "missing BPF lifecycle object at {} — run `cargo xtask build --bpf`",
        path.display()
    );
    let bytes = std::fs::read(&path).expect("test fixture must be readable");
    // Zero R_BPF_64_32 (type 10) across every SHT_REL section.
    let elf = goblin::elf::Elf::parse(&bytes).expect("valid ELF");
    let mut call_relocs = 0usize;
    for sh in elf.section_headers.iter() {
        if sh.sh_type != 9 {
            continue;
        }
        let base = sh.sh_offset as usize;
        for entry in 0..sh.sh_size as usize / 16 {
            let at = base + entry * 16;
            let info = u64::from_le_bytes(bytes[at + 8..at + 16].try_into().expect("rel entry"));
            if (info & 0xffff_ffff) as u32 == 10 {
                call_relocs += 1;
            }
        }
    }
    assert_eq!(call_relocs, 0, "kfunc stubs must carry no relocations");
    // Pinned sentinel sites + helper-only remainder, per program.
    let parsed = parse_lifecycle_object(&bytes).expect("built object must parse");
    assert_eq!(parsed.programs.len(), 12);
    for prog in &parsed.programs {
        let mut is_return = 0usize;
        let mut cookie = 0usize;
        for insn in &prog.insns {
            if insn.code != OP_CALL {
                continue;
            }
            match insn.imm {
                IS_RETURN => is_return += 1,
                COOKIE => cookie += 1,
                helper if helper > 0 && helper < 0x1000 => {}
                other => panic!(
                    "{}: call target {other:#x} is neither a pinned sentinel nor a helper id",
                    prog.section
                ),
            }
        }
        // P4: fsession programs pin 1 is_return + 2 cookie sites;
        // fentry callback programs pin NONE (plain entry args — no
        // session kfuncs exist for callbacks).
        let want = if prog.section.starts_with("fentry/") {
            (0, 0)
        } else {
            (1, 2)
        };
        assert_eq!(
            (is_return, cookie),
            want,
            "{}: want {want:?} session sites",
            prog.section
        );
    }
}

#[test]
fn bringup_resolve_finds_manifest_symbols() {
    // Profile-scoped resolution: exactly the manifest's symbols, no
    // more (unprivileged read; honest skip without host BTF).
    if std::fs::metadata("/sys/kernel/btf/vmlinux").is_err() {
        println!("SKIP: no /sys/kernel/btf/vmlinux on this host");
        return;
    }
    let ids = resolve_lifecycle_ids().expect("manifest symbols must resolve");
    assert_eq!(ids.len(), 10);
    assert!(ids.contains_key("crypto_skcipher_encrypt"));
    assert!(ids.contains_key("crypto_skcipher_decrypt"));
    assert!(ids.contains_key("crypto_alloc_skcipher"));
    assert!(ids.contains_key("crypto_destroy_tfm"));
    assert!(ids.contains_key("crypto_skcipher_setkey"));
    assert!(ids.contains_key("crypto_aead_setauthsize"));
    assert!(ids.contains_key("crypto_aead_setkey"));
    assert!(ids.contains_key("crypto_aead_encrypt"));
    assert!(ids.contains_key("crypto_aead_decrypt"));
    assert!(ids.contains_key("crypto_alloc_aead"));
    for (name, id) in &ids {
        assert_ne!(*id, 0, "{name} resolved to null id");
    }
}

#[test]
fn bringup_gate_passes_only_when_every_required_edge_loaded() {
    let loaded = |section: &str| {
        (
            section.to_owned(),
            PointStatus::Loaded {
                name: "test-prog".to_owned(),
            },
        )
    };
    let missing = |section: &str| {
        (
            section.to_owned(),
            PointStatus::Missing {
                name: "test-prog".to_owned(),
            },
        )
    };
    let all = [
        loaded("fsession/crypto_skcipher_encrypt"),
        loaded("fsession/crypto_skcipher_decrypt"),
        loaded("fsession/crypto_alloc_skcipher"),
        loaded("fsession/crypto_destroy_tfm"),
        loaded("fsession/crypto_skcipher_setkey"),
        loaded("fsession/crypto_aead_setauthsize"),
        loaded("fsession/crypto_aead_setkey"),
        loaded("fsession/crypto_aead_encrypt"),
        loaded("fsession/crypto_aead_decrypt"),
        loaded("fsession/crypto_alloc_aead"),
    ];
    let refs: Vec<(&str, &PointStatus)> = all.iter().map(|(s, st)| (s.as_str(), st)).collect();
    assert!(missing_required_points(&refs).is_empty());
    // One site missing → named.
    let refs: Vec<(&str, &PointStatus)> = refs[..9].to_vec();
    assert_eq!(
        missing_required_points(&refs),
        ["fsession/crypto_alloc_aead"]
    );
    // Unsupported counts as missing (refused load ≠ loaded point).
    let bad = [
        loaded("fsession/crypto_skcipher_encrypt"),
        missing("fsession/crypto_skcipher_decrypt"),
        loaded("fsession/crypto_alloc_skcipher"),
        loaded("fsession/crypto_destroy_tfm"),
        loaded("fsession/crypto_skcipher_setkey"),
        loaded("fsession/crypto_aead_setauthsize"),
        loaded("fsession/crypto_aead_setkey"),
        loaded("fsession/crypto_aead_encrypt"),
        loaded("fsession/crypto_aead_decrypt"),
        loaded("fsession/crypto_alloc_aead"),
    ];
    let refs: Vec<(&str, &PointStatus)> = bad.iter().map(|(s, st)| (s.as_str(), st)).collect();
    assert_eq!(
        missing_required_points(&refs),
        ["fsession/crypto_skcipher_decrypt"]
    );
}

#[test]
fn bringup_config_bytes_carry_exact_magic_version() {
    // The 80 bytes the loader writes to LCFG key 0: magic + version +
    // zero flags + the chase/refcount/request-link/request-metadata
    // words (P3 v4) + fixture-op words (P4 v5) + AEAD words (P5 v6)
    // + zero reserved tail — the exact words the BPF gate checks.
    let bytes = lifecycle_config_bytes(&test_offsets(), 0, false);
    assert_eq!(bytes.len(), 80);
    assert_eq!(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        0x3143_4c4b
    );
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 6);
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 32);
    assert_eq!(u32::from_le_bytes(bytes[16..20].try_into().unwrap()), 188);
    assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), 8);
    assert_eq!(u32::from_le_bytes(bytes[24..28].try_into().unwrap()), 40);
    assert_eq!(u32::from_le_bytes(bytes[28..32].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(bytes[32..36].try_into().unwrap()), 32);
    assert_eq!(u32::from_le_bytes(bytes[36..40].try_into().unwrap()), 32);
    assert_eq!(u32::from_le_bytes(bytes[40..44].try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(bytes[44..48].try_into().unwrap()), 40);
    assert_eq!(u32::from_le_bytes(bytes[56..60].try_into().unwrap()), 32);
    assert_eq!(u32::from_le_bytes(bytes[60..64].try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(bytes[64..68].try_into().unwrap()), 4);
    assert_eq!(u32::from_le_bytes(bytes[68..72].try_into().unwrap()), 8);
    assert_eq!(u32::from_le_bytes(bytes[72..76].try_into().unwrap()), 0);
    assert!(bytes[76..].iter().all(|b| *b == 0));
}

#[test]
fn h02_api_returns_shape_rejected_by_lifecycle_parse() {
    // Cross-discrimination: an fexit-only api-returns-shaped object is
    // not a lifecycle object (missing fsession sites + wrong sections).
    let bytes = build_lifecycle_fixture(
        &["fexit/crypto_alloc_tfm_node", "fexit/crypto_destroy_tfm"],
        LIFECYCLE_MAPS,
    );
    let err = parse_lifecycle_object(&bytes).expect_err("api-returns shape must refuse");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("fexit/crypto_alloc_tfm_node"),
        "refusal names the unsupported section: {msg}"
    );
}

/// Append `s` to a BTF string table; returns its offset.
fn btf_push_str(table: &mut Vec<u8>, s: &str) -> u32 {
    let off = table.len() as u32;
    table.extend_from_slice(s.as_bytes());
    table.push(0);
    off
}

/// Append one BTF type record (12-byte header + aux bytes).
fn btf_rec(types: &mut Vec<u8>, name_off: u32, kind: u8, vlen: u32, size_or_type: u32, aux: &[u8]) {
    types.extend_from_slice(&name_off.to_le_bytes());
    types.extend_from_slice(&(u32::from(kind) << 24 | vlen).to_le_bytes());
    types.extend_from_slice(&size_or_type.to_le_bytes());
    types.extend_from_slice(aux);
}

/// Wrap type + string sections in a 24-byte BTF header.
fn btf_image(types: &[u8], strtab: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xEB9Fu16.to_le_bytes());
    out.push(1);
    out.push(0);
    out.extend_from_slice(&24u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(types.len() as u32).to_le_bytes());
    out.extend_from_slice(&(types.len() as u32).to_le_bytes());
    out.extend_from_slice(&(strtab.len() as u32).to_le_bytes());
    out.extend_from_slice(types);
    out.extend_from_slice(strtab);
    out
}

/// Append the well-formed T07.4 configuration sides (hermetic:
/// every type the three FUNC_PROTOs name is defined inside this
/// block, so op/alloc-side mutations in the host builder never
/// disturb config validation — and config validation never depends
/// on host-builder type ids). `next` is the incoming next type id.
/// Layout (offsets from `next`): +0 STRUCT crypto_skcipher, +1
/// STRUCT crypto_aead, +2 PTR→+0, +3 PTR→+1, +4 INT char (1 byte),
/// +5 PTR→+4, +6 INT u32 (4 bytes, unsigned), +7 INT int (4 bytes,
/// SIGNED — the errno return), +8 setkey-sk FUNC_PROTO, +9
/// setkey-sk FUNC, +10 setauthsize FUNC_PROTO, +11 setauthsize
/// FUNC, +12 setkey-aead FUNC_PROTO, +13 setkey-aead FUNC.
/// Returns the outgoing next id.
/// Well-formed T07.4 configuration sides (14 ids at `next`):
/// setkey-sk, setauthsize, and setkey-aead FUNCs plus their local
/// types. T07-R4-N2: the block aliases the caller's FIRST
/// `crypto_skcipher` STRUCT (`sk_target`) via TYPEDEF instead of
/// emitting a rival STRUCT — every prototype root chases to the
/// same bound entry id (a rival same-named STRUCT would refuse).
fn append_config_sides(
    types: &mut Vec<u8>,
    strtab: &mut Vec<u8>,
    next: u32,
    sk_target: u32,
) -> u32 {
    let sk_off = btf_push_str(strtab, "crypto_skcipher");
    let aead_off = btf_push_str(strtab, "crypto_aead");
    let char_off = btf_push_str(strtab, "char");
    let u32_off = btf_push_str(strtab, "u32");
    let int_off = btf_push_str(strtab, "int");
    let skkey_off = btf_push_str(strtab, "crypto_skcipher_setkey");
    let sa_off = btf_push_str(strtab, "crypto_aead_setauthsize");
    let aeadkey_off = btf_push_str(strtab, "crypto_aead_setkey");
    btf_rec(types, sk_off, 8, 0, sk_target, &[]);
    btf_rec(types, aead_off, 4, 0, 0, &[]);
    btf_rec(types, 0, 2, 0, next, &[]);
    btf_rec(types, 0, 2, 0, next + 1, &[]);
    btf_rec(types, char_off, 1, 0, 1, &0x0100_0008u32.to_le_bytes());
    btf_rec(types, 0, 2, 0, next + 4, &[]);
    btf_rec(types, u32_off, 1, 0, 4, &0x0000_0020u32.to_le_bytes());
    btf_rec(types, int_off, 1, 0, 4, &0x0100_0020u32.to_le_bytes());
    let mut aux = Vec::new();
    for param in [next + 2, next + 5, next + 6] {
        aux.extend_from_slice(&0u32.to_le_bytes());
        aux.extend_from_slice(&param.to_le_bytes());
    }
    btf_rec(types, 0, 13, 3, next + 7, &aux);
    btf_rec(types, skkey_off, 12, 1, next + 8, &[]);
    let mut aux = Vec::new();
    for param in [next + 3, next + 6] {
        aux.extend_from_slice(&0u32.to_le_bytes());
        aux.extend_from_slice(&param.to_le_bytes());
    }
    btf_rec(types, 0, 13, 2, next + 7, &aux);
    btf_rec(types, sa_off, 12, 1, next + 10, &[]);
    let mut aux = Vec::new();
    for param in [next + 3, next + 5, next + 6] {
        aux.extend_from_slice(&0u32.to_le_bytes());
        aux.extend_from_slice(&param.to_le_bytes());
    }
    btf_rec(types, 0, 13, 3, next + 7, &aux);
    btf_rec(types, aeadkey_off, 12, 1, next + 12, &[]);
    next + 14
}

/// Append the well-formed P5 AEAD sides (hermetic: every type the
/// three FUNC_PROTOs name is defined inside this block, so
/// op/alloc/config-side mutations in the host builder never disturb
/// AEAD validation — and AEAD validation never depends on
/// host-builder type ids). `next` is the incoming next type id.
/// Layout (offsets from `next`): +0 TYPEDEF crypto_aead →
/// `aead_target` (T07-R4-N2: alias the caller's FIRST `crypto_aead`
/// STRUCT, never a rival def), +1 STRUCT aead_request (prototype
/// root only), +2 PTR→+1, +3 PTR→+0, +4 INT int (4 bytes, SIGNED —
/// the errno return), +5 INT char (1 byte), +6 PTR→+5, +7 INT u32
/// (4 bytes, unsigned), +8 op-aead FUNC_PROTO, +9 aead-encrypt
/// FUNC, +10 aead-decrypt FUNC, +11 alloc-aead FUNC_PROTO, +12
/// alloc-aead FUNC. Returns the outgoing next id.
fn append_aead_sides(
    types: &mut Vec<u8>,
    strtab: &mut Vec<u8>,
    next: u32,
    aead_target: u32,
) -> u32 {
    let aead_off = btf_push_str(strtab, "crypto_aead");
    let adreq_off = btf_push_str(strtab, "aead_request");
    let int_off = btf_push_str(strtab, "int");
    let char_off = btf_push_str(strtab, "char");
    let u32_off = btf_push_str(strtab, "u32");
    let enc_off = btf_push_str(strtab, "crypto_aead_encrypt");
    let dec_off = btf_push_str(strtab, "crypto_aead_decrypt");
    let alloc_off = btf_push_str(strtab, "crypto_alloc_aead");
    btf_rec(types, aead_off, 8, 0, aead_target, &[]);
    btf_rec(types, adreq_off, 4, 0, 0, &[]);
    btf_rec(types, 0, 2, 0, next + 1, &[]);
    btf_rec(types, 0, 2, 0, next, &[]);
    btf_rec(types, int_off, 1, 0, 4, &0x0100_0020u32.to_le_bytes());
    btf_rec(types, char_off, 1, 0, 1, &0x0100_0008u32.to_le_bytes());
    btf_rec(types, 0, 2, 0, next + 5, &[]);
    btf_rec(types, u32_off, 1, 0, 4, &0x0000_0020u32.to_le_bytes());
    let mut aux = Vec::new();
    aux.extend_from_slice(&0u32.to_le_bytes());
    aux.extend_from_slice(&(next + 2).to_le_bytes());
    btf_rec(types, 0, 13, 1, next + 4, &aux);
    btf_rec(types, enc_off, 12, 1, next + 8, &[]);
    btf_rec(types, dec_off, 12, 1, next + 8, &[]);
    let mut aux = Vec::new();
    for param in [next + 6, next + 7, next + 7] {
        aux.extend_from_slice(&0u32.to_le_bytes());
        aux.extend_from_slice(&param.to_le_bytes());
    }
    btf_rec(types, 0, 13, 3, next + 3, &aux);
    btf_rec(types, alloc_off, 12, 1, next + 11, &[]);
    next + 13
}

/// Minimal vmlinux-shaped BTF with the three lifecycle FUNCs. The
/// decrypt proto is always well-formed
/// (`int (struct skcipher_request *)`), and the alloc chain is always
/// well-formed (`struct crypto_skcipher *(const char *, u32, u32)`);
/// the encrypt side takes the given (return id, param-0 id, nargs,
/// func-target id, pointee id, INT data word, INT size) so refusal
/// shapes are fixture-exact. Type ids: 1 INT int, 2 STRUCT
/// skcipher_request, 3 PTR→pointee, 4 encrypt FUNC_PROTO, 5 encrypt
/// FUNC, 6 decrypt FUNC_PROTO, 7 decrypt FUNC, 8 STRUCT other_struct
/// (wrong-pointee control), 9 PTR→2 (decrypt's own pointer, so
/// encrypt-side pointee mutations never break the decrypt control),
/// 10 INT char, 11 PTR→10, 12 INT u32, 13 STRUCT crypto_skcipher, 14
/// PTR→13, 15 alloc FUNC_PROTO, 16 alloc FUNC, 17 STRUCT crypto_tfm,
/// 18 PTR→0 (`void *`), 19 PTR→17, 20 destroy FUNC_PROTO, 21
/// destroy FUNC.
fn lifecycle_btf(
    enc_ret: u32,
    enc_param: u32,
    enc_nargs: u32,
    enc_target: u32,
    ptr_target: u32,
    int_data: u32,
    int_size: u32,
) -> Vec<u8> {
    let mut strtab = vec![0u8];
    let int_off = btf_push_str(&mut strtab, "int");
    let req_off = btf_push_str(&mut strtab, "skcipher_request");
    let other_off = btf_push_str(&mut strtab, "other_struct");
    let enc_off = btf_push_str(&mut strtab, "crypto_skcipher_encrypt");
    let dec_off = btf_push_str(&mut strtab, "crypto_skcipher_decrypt");
    let char_off = btf_push_str(&mut strtab, "char");
    let u32_off = btf_push_str(&mut strtab, "u32");
    let sk_off = btf_push_str(&mut strtab, "crypto_skcipher");
    let alloc_off = btf_push_str(&mut strtab, "crypto_alloc_skcipher");
    let mut types = Vec::new();
    btf_rec(&mut types, int_off, 1, 0, int_size, &int_data.to_le_bytes());
    btf_rec(&mut types, req_off, 4, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, ptr_target, &[]);
    let mut aux = Vec::new();
    for _ in 0..enc_nargs {
        aux.extend_from_slice(&0u32.to_le_bytes());
        aux.extend_from_slice(&enc_param.to_le_bytes());
    }
    btf_rec(&mut types, 0, 13, enc_nargs, enc_ret, &aux);
    btf_rec(&mut types, enc_off, 12, 1, enc_target, &[]);
    let mut aux = Vec::new();
    aux.extend_from_slice(&0u32.to_le_bytes());
    aux.extend_from_slice(&9u32.to_le_bytes());
    btf_rec(&mut types, 0, 13, 1, 1, &aux);
    btf_rec(&mut types, dec_off, 12, 1, 6, &[]);
    btf_rec(&mut types, other_off, 4, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 2, &[]);
    btf_rec(&mut types, char_off, 1, 0, 1, &0x0100_0008u32.to_le_bytes());
    btf_rec(&mut types, 0, 2, 0, 10, &[]);
    btf_rec(&mut types, u32_off, 1, 0, 4, &0x0000_0020u32.to_le_bytes());
    btf_rec(&mut types, sk_off, 4, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 13, &[]);
    let mut aux = Vec::new();
    for param in [11u32, 12, 12] {
        aux.extend_from_slice(&0u32.to_le_bytes());
        aux.extend_from_slice(&param.to_le_bytes());
    }
    btf_rec(&mut types, 0, 13, 3, 14, &aux);
    btf_rec(&mut types, alloc_off, 12, 1, 15, &[]);
    // T07.3 destroy side (ids 17-21): well-formed
    // `void (void *, struct crypto_tfm *)` — STRUCT crypto_tfm
    // (17), `void *` PTR→0 (18), PTR→17 (19), the 2-arg VOID
    // FUNC_PROTO (20), and the destroy FUNC (21).
    let tfm_off = btf_push_str(&mut strtab, "crypto_tfm");
    let destroy_off = btf_push_str(&mut strtab, "crypto_destroy_tfm");
    btf_rec(&mut types, tfm_off, 4, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 17, &[]);
    let mut aux = Vec::new();
    for param in [18u32, 19] {
        aux.extend_from_slice(&0u32.to_le_bytes());
        aux.extend_from_slice(&param.to_le_bytes());
    }
    btf_rec(&mut types, 0, 13, 2, 0, &aux);
    btf_rec(&mut types, destroy_off, 12, 1, 20, &[]);
    // T07.4 configuration sides (ids 22-35): well-formed setkey-sk,
    // setauthsize, and setkey-aead FUNCs (hermetic block — op-side
    // mutations above never disturb config validation; the block
    // aliases STRUCT crypto_skcipher id 13).
    let next = append_config_sides(&mut types, &mut strtab, 22, 13);
    // P5 AEAD sides (ids 36-48): well-formed aead-encrypt/decrypt
    // and alloc-aead FUNCs (hermetic block — op-side mutations
    // above never disturb AEAD validation; the block aliases the
    // config block's STRUCT crypto_aead id 23).
    let _ = append_aead_sides(&mut types, &mut strtab, next, 23);
    btf_image(&types, &strtab)
}

/// Well-formed encrypt side: `int (struct skcipher_request *)` —
/// signed 32-bit INT (offset 0), PTR→STRUCT skcipher_request.
fn lifecycle_btf_good() -> Vec<u8> {
    lifecycle_btf(1, 3, 1, 4, 2, 0x0100_0020, 4)
}

/// Minimal vmlinux-shaped BTF with well-formed op FUNCs and a
/// mutated alloc chain: (return id, arg0 id, nargs, func-target id,
/// arg0-pointer target, arg1 id, arg2 id). Type ids: 1 INT int, 2
/// STRUCT skcipher_request, 3 PTR→2, 4 encrypt FUNC_PROTO, 5 encrypt
/// FUNC, 6 decrypt FUNC_PROTO, 7 decrypt FUNC, 8 STRUCT other_struct
/// (wrong-pointee control), 9 PTR→2, 10 INT char, 11 PTR→arg0-target,
/// 12 INT u32, 13 STRUCT crypto_skcipher, 14 PTR→13, 15 alloc
/// FUNC_PROTO, 16 alloc FUNC, 17 PTR→8 (wrong-return control), 18
/// STRUCT crypto_tfm, 19 PTR→0 (`void *`), 20 PTR→18, 21 destroy
/// FUNC_PROTO, 22 destroy FUNC.
fn lifecycle_btf_alloc(
    alloc_ret: u32,
    alloc_arg0: u32,
    alloc_nargs: u32,
    alloc_target: u32,
    arg0_ptr_target: u32,
    arg1_type: u32,
    arg2_type: u32,
) -> Vec<u8> {
    let mut strtab = vec![0u8];
    let int_off = btf_push_str(&mut strtab, "int");
    let req_off = btf_push_str(&mut strtab, "skcipher_request");
    let other_off = btf_push_str(&mut strtab, "other_struct");
    let enc_off = btf_push_str(&mut strtab, "crypto_skcipher_encrypt");
    let dec_off = btf_push_str(&mut strtab, "crypto_skcipher_decrypt");
    let char_off = btf_push_str(&mut strtab, "char");
    let u32_off = btf_push_str(&mut strtab, "u32");
    let sk_off = btf_push_str(&mut strtab, "crypto_skcipher");
    let alloc_off = btf_push_str(&mut strtab, "crypto_alloc_skcipher");
    let mut types = Vec::new();
    btf_rec(&mut types, int_off, 1, 0, 4, &0x0100_0020u32.to_le_bytes());
    btf_rec(&mut types, req_off, 4, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 2, &[]);
    let mut aux = Vec::new();
    aux.extend_from_slice(&0u32.to_le_bytes());
    aux.extend_from_slice(&3u32.to_le_bytes());
    btf_rec(&mut types, 0, 13, 1, 1, &aux);
    btf_rec(&mut types, enc_off, 12, 1, 4, &[]);
    let mut aux = Vec::new();
    aux.extend_from_slice(&0u32.to_le_bytes());
    aux.extend_from_slice(&9u32.to_le_bytes());
    btf_rec(&mut types, 0, 13, 1, 1, &aux);
    btf_rec(&mut types, dec_off, 12, 1, 6, &[]);
    btf_rec(&mut types, other_off, 4, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 2, &[]);
    btf_rec(&mut types, char_off, 1, 0, 1, &0x0100_0008u32.to_le_bytes());
    btf_rec(&mut types, 0, 2, 0, arg0_ptr_target, &[]);
    btf_rec(&mut types, u32_off, 1, 0, 4, &0x0000_0020u32.to_le_bytes());
    btf_rec(&mut types, sk_off, 4, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 13, &[]);
    let mut aux = Vec::new();
    // Arity mutations repeat arg0 (the encrypt-builder idiom); the
    // 3-arg shape carries the distinct arg ids.
    let params: Vec<u32> = if alloc_nargs == 3 {
        vec![alloc_arg0, arg1_type, arg2_type]
    } else {
        vec![alloc_arg0; alloc_nargs as usize]
    };
    for param in params {
        aux.extend_from_slice(&0u32.to_le_bytes());
        aux.extend_from_slice(&param.to_le_bytes());
    }
    btf_rec(&mut types, 0, 13, alloc_nargs, alloc_ret, &aux);
    btf_rec(&mut types, alloc_off, 12, 1, alloc_target, &[]);
    btf_rec(&mut types, 0, 2, 0, 8, &[]);
    // T07.3 destroy side (ids 18-22): well-formed
    // `void (void *, struct crypto_tfm *)`.
    let tfm_off = btf_push_str(&mut strtab, "crypto_tfm");
    let destroy_off = btf_push_str(&mut strtab, "crypto_destroy_tfm");
    btf_rec(&mut types, tfm_off, 4, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 18, &[]);
    let mut aux = Vec::new();
    for param in [19u32, 20] {
        aux.extend_from_slice(&0u32.to_le_bytes());
        aux.extend_from_slice(&param.to_le_bytes());
    }
    btf_rec(&mut types, 0, 13, 2, 0, &aux);
    btf_rec(&mut types, destroy_off, 12, 1, 21, &[]);
    // T07.4 configuration sides (ids 23-36): well-formed setkey-sk,
    // setauthsize, and setkey-aead FUNCs (hermetic block — alloc-side
    // mutations above never disturb config validation; the block
    // aliases STRUCT crypto_skcipher id 13).
    let next = append_config_sides(&mut types, &mut strtab, 23, 13);
    // P5 AEAD sides (ids 37-49): well-formed aead-encrypt/decrypt
    // and alloc-aead FUNCs (hermetic block — aliases the config
    // block's STRUCT crypto_aead id 24).
    let _ = append_aead_sides(&mut types, &mut strtab, next, 24);
    btf_image(&types, &strtab)
}

/// Well-formed alloc side: `struct crypto_skcipher *(const char *,
/// u32, u32)` over well-formed op FUNCs.
fn lifecycle_btf_alloc_good() -> Vec<u8> {
    lifecycle_btf_alloc(14, 11, 3, 15, 10, 12, 12)
}

/// Minimal vmlinux-shaped BTF with well-formed op/alloc/destroy
/// FUNCs (ids 1-21, the `lifecycle_btf` numbering) and a mutated
/// T07.4 configuration block (ids 22-39): the setkey-sk proto
/// takes (nargs, arg0, arg1, arg2, ret), the setauthsize proto
/// takes (nargs, arg0, arg1, ret), and the setkey-aead proto takes
/// arg0 with every other word well-formed. Config-block layout
/// (base 22): +0 TYPEDEF crypto_skcipher → 13 (T07-R4-N2: alias the
/// first STRUCT, never a rival def), +1 STRUCT crypto_aead, +2
/// STRUCT other_struct (wrong-struct control), +3 PTR→+0, +4
/// PTR→+1, +5 PTR→+2, +6 INT char, +7 PTR→+6, +8 INT u32, +9 INT
/// int (SIGNED errno), +10 INT u16 (narrow control), +11 INT uint
/// (unsigned control), +12 setkey-sk FUNC_PROTO, +13 setkey-sk
/// FUNC, +14 setauthsize FUNC_PROTO, +15 setauthsize FUNC, +16
/// setkey-aead FUNC_PROTO, +17 setkey-aead FUNC.
#[allow(clippy::too_many_arguments)]
fn lifecycle_btf_config(
    sk_nargs: u32,
    sk_arg0: u32,
    sk_arg1: u32,
    sk_arg2: u32,
    sk_ret: u32,
    sa_nargs: u32,
    sa_arg0: u32,
    sa_arg1: u32,
    sa_ret: u32,
    aead_arg0: u32,
) -> Vec<u8> {
    let mut strtab = vec![0u8];
    let int_off = btf_push_str(&mut strtab, "int");
    let req_off = btf_push_str(&mut strtab, "skcipher_request");
    let other_off = btf_push_str(&mut strtab, "other_struct");
    let enc_off = btf_push_str(&mut strtab, "crypto_skcipher_encrypt");
    let dec_off = btf_push_str(&mut strtab, "crypto_skcipher_decrypt");
    let char_off = btf_push_str(&mut strtab, "char");
    let u32_off = btf_push_str(&mut strtab, "u32");
    let sk_off = btf_push_str(&mut strtab, "crypto_skcipher");
    let alloc_off = btf_push_str(&mut strtab, "crypto_alloc_skcipher");
    let mut types = Vec::new();
    btf_rec(&mut types, int_off, 1, 0, 4, &0x0100_0020u32.to_le_bytes());
    btf_rec(&mut types, req_off, 4, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 2, &[]);
    let mut aux = Vec::new();
    aux.extend_from_slice(&0u32.to_le_bytes());
    aux.extend_from_slice(&3u32.to_le_bytes());
    btf_rec(&mut types, 0, 13, 1, 1, &aux);
    btf_rec(&mut types, enc_off, 12, 1, 4, &[]);
    let mut aux = Vec::new();
    aux.extend_from_slice(&0u32.to_le_bytes());
    aux.extend_from_slice(&9u32.to_le_bytes());
    btf_rec(&mut types, 0, 13, 1, 1, &aux);
    btf_rec(&mut types, dec_off, 12, 1, 6, &[]);
    btf_rec(&mut types, other_off, 4, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 2, &[]);
    btf_rec(&mut types, char_off, 1, 0, 1, &0x0100_0008u32.to_le_bytes());
    btf_rec(&mut types, 0, 2, 0, 10, &[]);
    btf_rec(&mut types, u32_off, 1, 0, 4, &0x0000_0020u32.to_le_bytes());
    btf_rec(&mut types, sk_off, 4, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 13, &[]);
    let mut aux = Vec::new();
    for param in [11u32, 12, 12] {
        aux.extend_from_slice(&0u32.to_le_bytes());
        aux.extend_from_slice(&param.to_le_bytes());
    }
    btf_rec(&mut types, 0, 13, 3, 14, &aux);
    btf_rec(&mut types, alloc_off, 12, 1, 15, &[]);
    let tfm_off = btf_push_str(&mut strtab, "crypto_tfm");
    let destroy_off = btf_push_str(&mut strtab, "crypto_destroy_tfm");
    btf_rec(&mut types, tfm_off, 4, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 17, &[]);
    let mut aux = Vec::new();
    for param in [18u32, 19] {
        aux.extend_from_slice(&0u32.to_le_bytes());
        aux.extend_from_slice(&param.to_le_bytes());
    }
    btf_rec(&mut types, 0, 13, 2, 0, &aux);
    btf_rec(&mut types, destroy_off, 12, 1, 20, &[]);
    // Config block (base 22): hermetic types, then the three
    // protos with the caller's knobs. Arity mutations repeat
    // arg0 (the alloc-builder idiom).
    let base = 22u32;
    let sk2_off = btf_push_str(&mut strtab, "crypto_skcipher");
    let aead_off = btf_push_str(&mut strtab, "crypto_aead");
    let other2_off = btf_push_str(&mut strtab, "other_struct");
    let char2_off = btf_push_str(&mut strtab, "char");
    let u32_2_off = btf_push_str(&mut strtab, "u32");
    let int2_off = btf_push_str(&mut strtab, "int");
    let u16_off = btf_push_str(&mut strtab, "u16");
    let uint_off = btf_push_str(&mut strtab, "uint");
    let skkey_off = btf_push_str(&mut strtab, "crypto_skcipher_setkey");
    let sa_off = btf_push_str(&mut strtab, "crypto_aead_setauthsize");
    let aeadkey_off = btf_push_str(&mut strtab, "crypto_aead_setkey");
    btf_rec(&mut types, sk2_off, 8, 0, 13, &[]);
    btf_rec(&mut types, aead_off, 4, 0, 0, &[]);
    btf_rec(&mut types, other2_off, 4, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, base, &[]);
    btf_rec(&mut types, 0, 2, 0, base + 1, &[]);
    btf_rec(&mut types, 0, 2, 0, base + 2, &[]);
    btf_rec(
        &mut types,
        char2_off,
        1,
        0,
        1,
        &0x0100_0008u32.to_le_bytes(),
    );
    btf_rec(&mut types, 0, 2, 0, base + 6, &[]);
    btf_rec(
        &mut types,
        u32_2_off,
        1,
        0,
        4,
        &0x0000_0020u32.to_le_bytes(),
    );
    btf_rec(&mut types, int2_off, 1, 0, 4, &0x0100_0020u32.to_le_bytes());
    btf_rec(&mut types, u16_off, 1, 0, 2, &0x0000_0010u32.to_le_bytes());
    btf_rec(&mut types, uint_off, 1, 0, 4, &0x0000_0020u32.to_le_bytes());
    let mut aux = Vec::new();
    let sk_params: Vec<u32> = if sk_nargs == 3 {
        vec![sk_arg0, sk_arg1, sk_arg2]
    } else {
        vec![sk_arg0; sk_nargs as usize]
    };
    for param in sk_params {
        aux.extend_from_slice(&0u32.to_le_bytes());
        aux.extend_from_slice(&param.to_le_bytes());
    }
    btf_rec(&mut types, 0, 13, sk_nargs, sk_ret, &aux);
    btf_rec(&mut types, skkey_off, 12, 1, base + 12, &[]);
    let mut aux = Vec::new();
    let sa_params: Vec<u32> = if sa_nargs == 2 {
        vec![sa_arg0, sa_arg1]
    } else {
        vec![sa_arg0; sa_nargs as usize]
    };
    for param in sa_params {
        aux.extend_from_slice(&0u32.to_le_bytes());
        aux.extend_from_slice(&param.to_le_bytes());
    }
    btf_rec(&mut types, 0, 13, sa_nargs, sa_ret, &aux);
    btf_rec(&mut types, sa_off, 12, 1, base + 14, &[]);
    let mut aux = Vec::new();
    for param in [aead_arg0, base + 7, base + 8] {
        aux.extend_from_slice(&0u32.to_le_bytes());
        aux.extend_from_slice(&param.to_le_bytes());
    }
    btf_rec(&mut types, 0, 13, 3, base + 9, &aux);
    btf_rec(&mut types, aeadkey_off, 12, 1, base + 16, &[]);
    // T07-R2-01 adversarial length: 4-byte storage with a shifted
    // 16-bit value (id base + 18 — appended AFTER the protos so no
    // existing id shifts).
    let narrow_off = btf_push_str(&mut strtab, "narrow_u32");
    btf_rec(
        &mut types,
        narrow_off,
        1,
        0,
        4,
        &0x0010_0010u32.to_le_bytes(),
    );
    // P5 AEAD sides (ids 41-53): well-formed aead-encrypt/decrypt
    // and alloc-aead FUNCs (hermetic block — config-side mutations
    // above never disturb AEAD validation; the block aliases the
    // config block's STRUCT crypto_aead id 23).
    let _ = append_aead_sides(&mut types, &mut strtab, 41, 23);
    btf_image(&types, &strtab)
}

/// Well-formed configuration sides: setkey-sk `(PTR→sk, PTR→char,
/// u32) → int`, setauthsize `(PTR→aead, u32) → int`, setkey-aead
/// `(PTR→aead, PTR→char, u32) → int`.
fn lifecycle_btf_config_good() -> Vec<u8> {
    lifecycle_btf_config(
        3, 25, 29, 30, 31, // setkey-sk: nargs, arg0, arg1, arg2, ret
        2, 26, 30, 31, // setauthsize: nargs, arg0, arg1, ret
        26, // setkey-aead arg0
    )
}

/// Assert the named configuration site refuses with `BadPrototype`.
fn assert_config_bad_proto(image: &[u8], site: &str, why: &str) {
    match resolve_lifecycle_ids_from(image) {
        Err(BtfError::BadPrototype { name, reason }) => {
            assert_eq!(name, site);
            assert!(
                !reason.is_empty(),
                "refusal names its reason ({why}): {reason}"
            );
        }
        other => panic!("want BadPrototype for {site}, got {other:?} ({why})"),
    }
}

/// Assert the alloc side refuses with `BadPrototype` naming it.
fn assert_alloc_bad_proto(image: &[u8], why: &str) {
    match resolve_lifecycle_ids_from(image) {
        Err(BtfError::BadPrototype { name, reason }) => {
            assert_eq!(name, "crypto_alloc_skcipher");
            assert!(
                !reason.is_empty(),
                "refusal names its reason ({why}): {reason}"
            );
        }
        other => panic!("want BadPrototype, got {other:?} ({why})"),
    }
}

#[test]
fn f2_alloc_wellformed_proto_resolves() {
    // Control: the alloc shape resolves alongside the op sites.
    let ids = resolve_lifecycle_ids_from(&lifecycle_btf_alloc_good()).expect("good alloc proto");
    assert_eq!(ids.len(), 10);
    assert_eq!(ids["crypto_alloc_skcipher"], 16);
    assert_eq!(ids["crypto_destroy_tfm"], 22);
    assert_eq!(ids["crypto_aead_encrypt"], 46);
    assert_eq!(ids["crypto_alloc_aead"], 49);
}

#[test]
fn f2_alloc_non_pointer_arg0_refused() {
    // The name copy reads through arg0 — an INT arg0 must refuse.
    assert_alloc_bad_proto(&lifecycle_btf_alloc(14, 1, 3, 15, 10, 12, 12), "INT arg0");
}

#[test]
fn f2_alloc_wrong_arity_refused() {
    // Two args is not the alloc shape (type/mask would mis-shift).
    assert_alloc_bad_proto(
        &lifecycle_btf_alloc(14, 11, 2, 15, 10, 12, 12),
        "2-arg proto",
    );
}

#[test]
fn f2_alloc_wide_arg0_pointee_refused() {
    // The name copy reads bytes: a 4-byte pointee changes what the
    // byte copy means.
    assert_alloc_bad_proto(
        &lifecycle_btf_alloc(14, 11, 3, 15, 1, 12, 12),
        "INT pointee",
    );
}

#[test]
fn f2_alloc_non_int_arg1_refused() {
    // The type word must be a 4-byte scalar, not a pointer.
    assert_alloc_bad_proto(&lifecycle_btf_alloc(14, 11, 3, 15, 10, 11, 12), "PTR arg1");
}

#[test]
fn f2_alloc_non_pointer_return_refused() {
    // An INT return has no tfm to chase on success.
    assert_alloc_bad_proto(&lifecycle_btf_alloc(1, 11, 3, 15, 10, 12, 12), "INT return");
}

#[test]
fn f2_alloc_wrong_return_struct_refused() {
    // The success chase reads `__crt_alg` — a pointer to any other
    // struct would mis-chase.
    assert_alloc_bad_proto(
        &lifecycle_btf_alloc(17, 11, 3, 15, 10, 12, 12),
        "other_struct return",
    );
}

#[test]
fn f2_alloc_func_to_non_proto_refused() {
    // A FUNC whose target is not a FUNC_PROTO has no prototype.
    assert_alloc_bad_proto(
        &lifecycle_btf_alloc(14, 11, 3, 14, 10, 12, 12),
        "non-proto target",
    );
}

#[test]
fn f2_wellformed_protos_resolve_all_ids() {
    // Control: int (struct skcipher_request *) on both op sites plus
    // the alloc shape resolves.
    let ids = resolve_lifecycle_ids_from(&lifecycle_btf_good()).expect("good protos");
    assert_eq!(ids.len(), 10);
    assert_eq!(ids["crypto_skcipher_encrypt"], 5);
    assert_eq!(ids["crypto_skcipher_decrypt"], 7);
    assert_eq!(ids["crypto_alloc_skcipher"], 16);
    assert_eq!(ids["crypto_destroy_tfm"], 21);
    assert_eq!(ids["crypto_aead_encrypt"], 45);
    assert_eq!(ids["crypto_alloc_aead"], 48);
}

#[test]
fn f2_non_pointer_arg0_refused() {
    // Round-1 (sol-M2/astra-M2): the BPF reads arg(0) as the request
    // key — an INT arg0 must refuse startup, not mis-key the join.
    match resolve_lifecycle_ids_from(&lifecycle_btf(1, 1, 1, 4, 2, 0x0100_0020, 4)) {
        Err(BtfError::BadPrototype { name, .. }) => {
            assert_eq!(name, "crypto_skcipher_encrypt");
        }
        other => panic!("want BadPrototype, got {other:?}"),
    }
}

#[test]
fn f2_non_int_return_refused() {
    // A VOID return cannot be cast to the native i32 status.
    match resolve_lifecycle_ids_from(&lifecycle_btf(0, 3, 1, 4, 2, 0x0100_0020, 4)) {
        Err(BtfError::BadPrototype { name, .. }) => {
            assert_eq!(name, "crypto_skcipher_encrypt");
        }
        other => panic!("want BadPrototype, got {other:?}"),
    }
}

#[test]
fn f2_zero_arg_proto_refused() {
    // No args: there is no arg(0) key to read at all.
    match resolve_lifecycle_ids_from(&lifecycle_btf(1, 3, 0, 4, 2, 0x0100_0020, 4)) {
        Err(BtfError::BadPrototype { name, .. }) => {
            assert_eq!(name, "crypto_skcipher_encrypt");
        }
        other => panic!("want BadPrototype, got {other:?}"),
    }
}

#[test]
fn f2_func_to_non_proto_refused() {
    // A FUNC whose target is not a FUNC_PROTO has no prototype.
    match resolve_lifecycle_ids_from(&lifecycle_btf(1, 3, 1, 1, 2, 0x0100_0020, 4)) {
        Err(BtfError::BadPrototype { name, .. }) => {
            assert_eq!(name, "crypto_skcipher_encrypt");
        }
        other => panic!("want BadPrototype, got {other:?}"),
    }
}

#[test]
fn f2_typedef_wrapped_pointer_arg_accepted() {
    // Qualifier chase control: arg0 through `typedef PTR req_ptr`
    // still resolves (the chase is real, not refusal-only).
    let mut strtab = vec![0u8];
    let int_off = btf_push_str(&mut strtab, "int");
    let req_off = btf_push_str(&mut strtab, "skcipher_request");
    let alias_off = btf_push_str(&mut strtab, "req_ptr");
    let enc_off = btf_push_str(&mut strtab, "crypto_skcipher_encrypt");
    let dec_off = btf_push_str(&mut strtab, "crypto_skcipher_decrypt");
    let char_off = btf_push_str(&mut strtab, "char");
    let u32_off = btf_push_str(&mut strtab, "u32");
    let sk_off = btf_push_str(&mut strtab, "crypto_skcipher");
    let alloc_off = btf_push_str(&mut strtab, "crypto_alloc_skcipher");
    let mut types = Vec::new();
    btf_rec(&mut types, int_off, 1, 0, 4, &0x0100_0020u32.to_le_bytes());
    btf_rec(&mut types, req_off, 4, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 2, &[]);
    // id 4: encrypt proto with arg0 = typedef id 8 (emitted below as
    // id 8; forward refs are legal BTF).
    let mut aux = Vec::new();
    aux.extend_from_slice(&0u32.to_le_bytes());
    aux.extend_from_slice(&8u32.to_le_bytes());
    btf_rec(&mut types, 0, 13, 1, 1, &aux);
    btf_rec(&mut types, enc_off, 12, 1, 4, &[]);
    let mut aux = Vec::new();
    aux.extend_from_slice(&0u32.to_le_bytes());
    aux.extend_from_slice(&3u32.to_le_bytes());
    btf_rec(&mut types, 0, 13, 1, 1, &aux);
    btf_rec(&mut types, dec_off, 12, 1, 6, &[]);
    // id 8: TYPEDEF req_ptr -> 3.
    btf_rec(&mut types, alias_off, 8, 0, 3, &[]);
    // ids 9-15: well-formed alloc chain (the resolve needs every
    // manifest FUNC present).
    btf_rec(&mut types, char_off, 1, 0, 1, &0x0100_0008u32.to_le_bytes());
    btf_rec(&mut types, 0, 2, 0, 9, &[]);
    btf_rec(&mut types, u32_off, 1, 0, 4, &0x0000_0020u32.to_le_bytes());
    btf_rec(&mut types, sk_off, 4, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 12, &[]);
    let mut aux = Vec::new();
    for param in [10u32, 11, 11] {
        aux.extend_from_slice(&0u32.to_le_bytes());
        aux.extend_from_slice(&param.to_le_bytes());
    }
    btf_rec(&mut types, 0, 13, 3, 13, &aux);
    btf_rec(&mut types, alloc_off, 12, 1, 14, &[]);
    // T07.3 destroy side (ids 16-20): well-formed
    // `void (void *, struct crypto_tfm *)`.
    let tfm_off = btf_push_str(&mut strtab, "crypto_tfm");
    let destroy_off = btf_push_str(&mut strtab, "crypto_destroy_tfm");
    btf_rec(&mut types, tfm_off, 4, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 0, &[]);
    btf_rec(&mut types, 0, 2, 0, 16, &[]);
    let mut aux = Vec::new();
    for param in [17u32, 18] {
        aux.extend_from_slice(&0u32.to_le_bytes());
        aux.extend_from_slice(&param.to_le_bytes());
    }
    btf_rec(&mut types, 0, 13, 2, 0, &aux);
    btf_rec(&mut types, destroy_off, 12, 1, 19, &[]);
    // T07.4 configuration sides (ids 21-34): well-formed setkey-sk,
    // setauthsize, and setkey-aead FUNCs (hermetic block aliasing
    // STRUCT crypto_skcipher id 12).
    let next = append_config_sides(&mut types, &mut strtab, 21, 12);
    // P5 AEAD sides (ids 35-47): well-formed aead-encrypt/decrypt
    // and alloc-aead FUNCs (hermetic block aliasing STRUCT
    // crypto_aead id 22).
    let _ = append_aead_sides(&mut types, &mut strtab, next, 22);
    let ids = resolve_lifecycle_ids_from(&btf_image(&types, &strtab)).expect("chased proto");
    assert_eq!(ids.len(), 10);
    assert_eq!(ids["crypto_alloc_skcipher"], 15);
    assert_eq!(ids["crypto_destroy_tfm"], 20);
    assert_eq!(ids["crypto_skcipher_setkey"], 30);
    assert_eq!(ids["crypto_aead_setauthsize"], 32);
    assert_eq!(ids["crypto_aead_setkey"], 34);
    assert_eq!(ids["crypto_aead_encrypt"], 44);
    assert_eq!(ids["crypto_alloc_aead"], 47);
}

/// Assert the encrypt side refuses with `BadPrototype` naming it.
fn assert_encrypt_bad_proto(image: &[u8], why: &str) {
    match resolve_lifecycle_ids_from(image) {
        Err(BtfError::BadPrototype { name, reason }) => {
            assert_eq!(name, "crypto_skcipher_encrypt");
            assert!(
                !reason.is_empty(),
                "refusal names its reason ({why}): {reason}"
            );
        }
        other => panic!("want BadPrototype ({why}), got {other:?}"),
    }
}

#[test]
fn w2_extra_arg_proto_refused() {
    // Round-2 (sol-M4/astra-M7): the qualified prototype takes
    // EXACTLY one argument — a two-arg variant refuses startup
    // rather than attaching to a changed signature.
    assert_encrypt_bad_proto(&lifecycle_btf(1, 3, 2, 4, 2, 0x0100_0020, 4), "extra arg");
}

#[test]
fn w2_non_struct_pointee_refused() {
    // arg0 must point at STRUCT skcipher_request (the qualified
    // request identity) — a pointer to INT refuses.
    assert_encrypt_bad_proto(&lifecycle_btf(1, 3, 1, 4, 1, 0x0100_0020, 4), "INT pointee");
}

#[test]
fn w2_wrong_struct_pointee_refused() {
    // Same-kind wrong identity: a pointer to another STRUCT refuses
    // — the name is part of the qualification, not just the kind.
    assert_encrypt_bad_proto(
        &lifecycle_btf(1, 3, 1, 4, 8, 0x0100_0020, 4),
        "wrong STRUCT",
    );
}

#[test]
fn w2_unsigned_return_refused() {
    // The native status is a SIGNED int: encoding 0 (unsigned/none)
    // refuses — a sign change would invert errno reads.
    assert_encrypt_bad_proto(
        &lifecycle_btf(1, 3, 1, 4, 2, 0x0000_0020, 4),
        "unsigned INT",
    );
}

#[test]
fn w2_offset_return_refused() {
    // A bit-offset INT is a bitfield, not a status word.
    assert_encrypt_bad_proto(&lifecycle_btf(1, 3, 1, 4, 2, 0x0101_0020, 4), "offset INT");
}

#[test]
fn w2_narrow_return_refused() {
    // 16-bit status would truncate errnos.
    assert_encrypt_bad_proto(&lifecycle_btf(1, 3, 1, 4, 2, 0x0100_0010, 2), "16-bit INT");
}

#[test]
fn w3_combined_encoding_return_refused() {
    // Round-3 minor: the gate tests the encoding EXACTLY, not the
    // SIGNED bit — SIGNED combined with CHAR (0x03) or BOOL (0x05)
    // is a different type, not a status word.
    assert_encrypt_bad_proto(
        &lifecycle_btf(1, 3, 1, 4, 2, 0x0300_0020, 4),
        "SIGNED|CHAR INT",
    );
    assert_encrypt_bad_proto(
        &lifecycle_btf(1, 3, 1, 4, 2, 0x0500_0020, 4),
        "SIGNED|BOOL INT",
    );
}

#[test]
fn t74_wellformed_config_protos_resolve_all_ids() {
    // Control: the three configuration shapes resolve alongside
    // the op/alloc/destroy sites.
    let ids = resolve_lifecycle_ids_from(&lifecycle_btf_config_good()).expect("good config protos");
    assert_eq!(ids.len(), 10);
    assert_eq!(ids["crypto_skcipher_setkey"], 35);
    assert_eq!(ids["crypto_aead_setauthsize"], 37);
    assert_eq!(ids["crypto_aead_setkey"], 39);
    assert_eq!(ids["crypto_aead_encrypt"], 50);
    assert_eq!(ids["crypto_alloc_aead"], 53);
}

#[test]
fn t74_setkey_wrong_arity_refused() {
    // Two args is not the setkey shape (key/len would mis-shift).
    assert_config_bad_proto(
        &lifecycle_btf_config(2, 25, 29, 30, 31, 2, 26, 30, 31, 26),
        "crypto_skcipher_setkey",
        "2-arg proto",
    );
}

#[test]
fn t74_setkey_non_pointer_arg0_refused() {
    // The epoch joins on the frontend address — an INT arg0 must refuse.
    assert_config_bad_proto(
        &lifecycle_btf_config(3, 31, 29, 30, 31, 2, 26, 30, 31, 26),
        "crypto_skcipher_setkey",
        "INT arg0",
    );
}

#[test]
fn t74_setkey_wrong_struct_arg0_refused() {
    // A pointer to any other STRUCT keys the epoch on a stranger.
    assert_config_bad_proto(
        &lifecycle_btf_config(3, 27, 29, 30, 31, 2, 26, 30, 31, 26),
        "crypto_skcipher_setkey",
        "other_struct arg0",
    );
}

#[test]
fn t74_setkey_aead_struct_arg0_refused() {
    // Same-kind wrong identity: the skcipher site refuses an AEAD
    // frontend — the STRUCT name is part of the qualification.
    assert_config_bad_proto(
        &lifecycle_btf_config(3, 26, 29, 30, 31, 2, 26, 30, 31, 26),
        "crypto_skcipher_setkey",
        "aead STRUCT at sk site",
    );
}

#[test]
fn t74_setkey_non_pointer_key_refused() {
    // The key buffer pins the register shape as a pointer (its
    // pointee stays unread — but a non-pointer arg1 is drift).
    assert_config_bad_proto(
        &lifecycle_btf_config(3, 25, 31, 30, 31, 2, 26, 30, 31, 26),
        "crypto_skcipher_setkey",
        "INT arg1",
    );
}

#[test]
fn t74_setkey_non_int_len_refused() {
    // The key length must be a scalar, not a pointer.
    assert_config_bad_proto(
        &lifecycle_btf_config(3, 25, 29, 29, 31, 2, 26, 30, 31, 26),
        "crypto_skcipher_setkey",
        "PTR arg2",
    );
}

#[test]
fn t74_setkey_narrow_len_refused() {
    // A 16-bit length would truncate key sizes.
    assert_config_bad_proto(
        &lifecycle_btf_config(3, 25, 29, 32, 31, 2, 26, 30, 31, 26),
        "crypto_skcipher_setkey",
        "16-bit arg2",
    );
}

#[test]
fn t74_setkey_shifted_len_refused() {
    // T07-R2-01: 4-byte storage with a shifted 16-bit value is
    // not a length word — the unshifted u32 copy would misread
    // it exactly like a narrowed counter.
    assert_config_bad_proto(
        &lifecycle_btf_config(3, 25, 29, 40, 31, 2, 26, 30, 31, 26),
        "crypto_skcipher_setkey",
        "shifted 16-bit arg2",
    );
}

#[test]
fn t74_setkey_void_return_refused() {
    // No errno, no success/failure verdict — VOID refuses.
    assert_config_bad_proto(
        &lifecycle_btf_config(3, 25, 29, 30, 0, 2, 26, 30, 31, 26),
        "crypto_skcipher_setkey",
        "VOID return",
    );
}

#[test]
fn t74_setkey_unsigned_return_refused() {
    // The native status is SIGNED: an unsigned return would invert
    // errno reads.
    assert_config_bad_proto(
        &lifecycle_btf_config(3, 25, 29, 30, 33, 2, 26, 30, 31, 26),
        "crypto_skcipher_setkey",
        "unsigned INT return",
    );
}

#[test]
fn t74_setauthsize_wrong_arity_refused() {
    // Three args is not the setauthsize shape.
    assert_config_bad_proto(
        &lifecycle_btf_config(3, 25, 29, 30, 31, 3, 26, 30, 31, 26),
        "crypto_aead_setauthsize",
        "3-arg proto",
    );
}

#[test]
fn t74_setauthsize_wrong_struct_arg0_refused() {
    // A pointer to any other STRUCT keys the epoch on a stranger.
    assert_config_bad_proto(
        &lifecycle_btf_config(3, 25, 29, 30, 31, 2, 27, 30, 31, 26),
        "crypto_aead_setauthsize",
        "other_struct arg0",
    );
}

#[test]
fn t74_setauthsize_non_int_arg1_refused() {
    // The authsize must be a scalar, not a pointer.
    assert_config_bad_proto(
        &lifecycle_btf_config(3, 25, 29, 30, 31, 2, 26, 29, 31, 26),
        "crypto_aead_setauthsize",
        "PTR arg1",
    );
}

#[test]
fn t74_setauthsize_void_return_refused() {
    assert_config_bad_proto(
        &lifecycle_btf_config(3, 25, 29, 30, 31, 2, 26, 30, 0, 26),
        "crypto_aead_setauthsize",
        "VOID return",
    );
}

#[test]
fn t74_setkey_aead_sk_struct_arg0_refused() {
    // Cross-check the frontend parameter: the AEAD site refuses a
    // skcipher frontend — setkey-sk and setkey-aead pin DIFFERENT
    // identities.
    assert_config_bad_proto(
        &lifecycle_btf_config(3, 25, 29, 30, 31, 2, 26, 30, 31, 25),
        "crypto_aead_setkey",
        "skcipher STRUCT at aead site",
    );
}

#[test]
fn f8a_profile_parse_round_trips_both_names() {
    // Round-1 (sol-M5/astra-M8): registry/live entry points select
    // the profile by NAME; the spelling is exact, garbage refuses.
    assert_eq!(
        LifecycleProfile::parse("api-returns"),
        Some(LifecycleProfile::ApiReturns)
    );
    assert_eq!(
        LifecycleProfile::parse("request-lifecycle"),
        Some(LifecycleProfile::RequestLifecycle)
    );
    assert_eq!(LifecycleProfile::parse("lifecycle"), None);
    assert_eq!(LifecycleProfile::parse(""), None);
    assert_eq!(LifecycleProfile::ApiReturns.as_str(), "api-returns");
    assert_eq!(
        LifecycleProfile::RequestLifecycle.as_str(),
        "request-lifecycle"
    );
    assert_eq!(LifecycleProfile::default(), LifecycleProfile::ApiReturns);
}

#[test]
fn f8b_cross_profile_sessions_exclude_same_process() {
    // Round-1 (sol-M5/astra-M8): no cross-profile capture — a live
    // api-returns session refuses a request-lifecycle bring-up in the
    // same process and vice versa. ApiReturns holders share (today's
    // aggregate concurrency is unchanged), but RequestLifecycle is
    // single-owner (H5: a second lifecycle sensor would double-capture
    // through retired trampolines); dropping every holder releases the
    // process for the other profile. Single test: the guard is
    // process-global, so the sequence must not interleave.
    let agg = acquire_kcrypto_session(LifecycleProfile::ApiReturns).expect("first holder");
    assert!(matches!(
        acquire_kcrypto_session(LifecycleProfile::RequestLifecycle),
        Err(SessionBusy { .. })
    ));
    let agg2 = acquire_kcrypto_session(LifecycleProfile::ApiReturns).expect("same-profile shares");
    drop(agg);
    assert!(acquire_kcrypto_session(LifecycleProfile::RequestLifecycle).is_err());
    drop(agg2);
    let life = acquire_kcrypto_session(LifecycleProfile::RequestLifecycle).expect("released");
    assert!(acquire_kcrypto_session(LifecycleProfile::ApiReturns).is_err());
    // H5: a second lifecycle holder refuses (same-profile exclusion).
    assert!(matches!(
        acquire_kcrypto_session(LifecycleProfile::RequestLifecycle),
        Err(SessionBusy { .. })
    ));
    drop(life);
    assert!(acquire_kcrypto_session(LifecycleProfile::ApiReturns).is_ok());
}
