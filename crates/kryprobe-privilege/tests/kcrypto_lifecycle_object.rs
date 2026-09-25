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
    BtfError, resolve_lifecycle_ids, resolve_lifecycle_ids_from,
};
use kryprobe_privilege::kcrypto_lifecycle::profile::{
    ConfigVerifyError, LCFG_VALUE_LEN, LIFECYCLE_MAPS, LifecycleProfile, SessionBusy,
    acquire_kcrypto_session, lifecycle_config_bytes, manifest, max_programs,
    missing_required_points, parse_lifecycle_object, required_gate_error, section_allowed,
    validate_lifecycle_config, validate_member, verify_lifecycle_config_bytes,
};

#[test]
fn h01_lifecycle_manifest_requires_both_edges_per_site() {
    // The T06 profile observes the two T04-qualified api sites, each at
    // entry AND return; anything less cannot pair submit with result.
    let m = manifest(LifecycleProfile::RequestLifecycle);
    assert_eq!(m.name, "request-lifecycle");
    let sites: Vec<(&str, bool, bool)> = m
        .required
        .iter()
        .map(|s| (s.symbol, s.entry, s.exit))
        .collect();
    assert_eq!(
        sites,
        [
            ("crypto_skcipher_encrypt", true, true),
            ("crypto_skcipher_decrypt", true, true),
        ]
    );
}

#[test]
fn h01_program_limit_derives_from_manifest_not_global_cap() {
    // 2 sites x 2 edges = 4; the api-returns 16-program cap is a
    // different profile's limit and must not leak across.
    let lc = manifest(LifecycleProfile::RequestLifecycle);
    assert_eq!(max_programs(&lc), 4);
    let api = manifest(LifecycleProfile::ApiReturns);
    assert_eq!(max_programs(&api), 16);
    assert_ne!(max_programs(&lc), max_programs(&api));
}

#[test]
fn h01_lifecycle_sections_accept_entry_and_return_pairs() {
    let p = LifecycleProfile::RequestLifecycle;
    assert!(section_allowed(p, "fentry/crypto_skcipher_encrypt"));
    assert!(section_allowed(p, "fexit/crypto_skcipher_encrypt"));
    assert!(section_allowed(p, "fentry/crypto_skcipher_decrypt"));
    assert!(section_allowed(p, "fexit/crypto_skcipher_decrypt"));
    assert!(!section_allowed(p, "fentry/"));
    assert!(!section_allowed(p, "fexit/"));
    assert!(!section_allowed(p, "fentry"));
    assert!(!section_allowed(p, "fexit"));
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
    assert!(!section_allowed(p, "uprobe.multi"));
    assert!(!section_allowed(p, "fexit"));
    assert!(!section_allowed(p, ""));
}

#[test]
fn h01_lifecycle_map_table_is_exact_and_dot_free() {
    // LCFG (config), LRING (edge ringbuf), LLOSS (per-CPU loss,
    // 5 classes), LSTATE (global identity slots, packed words),
    // LAGG (per-CPU accepted aggregate), LCTR (per-CPU invocation
    // sequence), LQ (NOSLOT ghost quarantine), LGLB
    // (quarantine-overflow flag): the T06 contract the BPF object
    // must match byte-for-byte.
    assert_eq!(LIFECYCLE_MAPS.len(), 8);
    let names: Vec<&str> = LIFECYCLE_MAPS.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        names,
        [
            "LCFG", "LRING", "LLOSS", "LSTATE", "LAGG", "LCTR", "LQ", "LGLB"
        ]
    );
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
            value_size: 64,
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
            max_entries: 5,
        }
    );
    assert_eq!(
        dims("LSTATE"),
        MapDims {
            map_type: 1,
            key_size: 8,
            value_size: 8,
            max_entries: 4096,
        }
    );
    assert_eq!(
        dims("LAGG"),
        MapDims {
            map_type: 6,
            key_size: 4,
            value_size: 8,
            max_entries: 4,
        }
    );
    assert_eq!(
        dims("LCTR"),
        MapDims {
            map_type: 6,
            key_size: 4,
            value_size: 8,
            max_entries: 1,
        }
    );
    assert_eq!(
        dims("LQ"),
        MapDims {
            map_type: 1,
            key_size: 8,
            value_size: 1,
            max_entries: 4096,
        }
    );
    assert_eq!(
        dims("LGLB"),
        MapDims {
            map_type: 2,
            key_size: 4,
            value_size: 8,
            max_entries: 1,
        }
    );
}

#[test]
fn h01_zeroed_config_fails_closed() {
    // All-zero LCFG (unwritten map read-back) never arms the sensor;
    // only the exact magic+version arms it.
    assert!(validate_lifecycle_config(0, 0, 0).is_err());
    assert!(validate_lifecycle_config(0x31434c4b, 0, 0).is_err());
    assert!(validate_lifecycle_config(0, 1, 0).is_err());
    assert!(validate_lifecycle_config(0x31434c4b, 1, 0).is_ok());
}

#[test]
fn f1_lcfg_readback_validates_full_64_bytes() {
    // Round-1 finding (sol-M1/astra-M1): the verify path read the
    // 64-byte LCFG value into an 8-byte u64 (56-byte stack overwrite).
    // The read-back verifier takes the full 64 bytes: short reads fail
    // closed, and every word (magic/version/flags/reserved) must match.
    let good = lifecycle_config_bytes();
    assert_eq!(good.len(), 64);
    assert!(verify_lifecycle_config_bytes(&good).is_ok());
    assert!(matches!(
        verify_lifecycle_config_bytes(&good[..8]),
        Err(ConfigVerifyError::BadLength { got: 8 })
    ));
    assert!(matches!(
        verify_lifecycle_config_bytes(&[0u8; 64]),
        Err(ConfigVerifyError::BadMagic)
    ));
    let mut bad_version = good;
    bad_version[4] = 0x7f;
    assert!(matches!(
        verify_lifecycle_config_bytes(&bad_version),
        Err(ConfigVerifyError::BadVersion)
    ));
    let mut bad_flags = good;
    bad_flags[8] = 1;
    assert!(matches!(
        verify_lifecycle_config_bytes(&bad_flags),
        Err(ConfigVerifyError::BadFlags)
    ));
    let mut bad_reserved = good;
    bad_reserved[63] = 1;
    assert!(matches!(
        verify_lifecycle_config_bytes(&bad_reserved),
        Err(ConfigVerifyError::BadReserved { offset: 63 })
    ));
}

#[test]
fn f10_required_gate_preserves_load_error_type() {
    // Round-1 (sol-m10/astra-m10): a required point's load refusal
    // must surface typed (errno + verifier tail), not as a
    // shape-flavored BadObject. Shape-only misses stay BadObject.
    let missing = vec!["fentry/crypto_skcipher_encrypt".to_owned()];
    let load_errors = vec![(
        "fentry/crypto_skcipher_encrypt".to_owned(),
        LoaderError::LoadFailed {
            stage: "kcrypto_encrypt_entry".to_owned(),
            errno: 13,
            log: "verifier tail".to_owned(),
        },
    )];
    match required_gate_error(&missing, &load_errors) {
        LoaderError::LoadFailed { stage, errno, log } => {
            assert_eq!(errno, 13);
            assert_eq!(log, "verifier tail");
            assert!(stage.contains("fentry/crypto_skcipher_encrypt"), "{stage}");
        }
        other => panic!("want LoadFailed, got {other:?}"),
    }
    match required_gate_error(&missing, &[]) {
        LoaderError::BadObject { reason } => {
            assert!(
                reason.contains("fentry/crypto_skcipher_encrypt"),
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
    assert_eq!(lifecycle_config_bytes().len(), LCFG_VALUE_LEN);
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

/// The T06 contract as a fixture: both edges for both api sites plus
/// the exact frozen map table.
fn valid_lifecycle_fixture() -> Vec<u8> {
    let maps: Vec<(&str, MapDims)> = LIFECYCLE_MAPS.to_vec();
    build_lifecycle_fixture(
        &[
            "fentry/crypto_skcipher_encrypt",
            "fexit/crypto_skcipher_encrypt",
            "fentry/crypto_skcipher_decrypt",
            "fexit/crypto_skcipher_decrypt",
        ],
        &maps,
    )
}

#[test]
fn h02_valid_entry_return_object_parses() {
    let bytes = valid_lifecycle_fixture();
    let parsed = parse_lifecycle_object(&bytes).expect("valid fixture must parse");
    assert_eq!(parsed.maps.len(), 8);
    assert_eq!(parsed.programs.len(), 4);
    for prog in &parsed.programs {
        assert_eq!(prog.insns.len(), 1, "{} stream drifted", prog.name);
    }
    assert!(parsed.map_relocs.is_empty());
}

#[test]
fn h02_missing_required_site_refused_by_name() {
    let maps: Vec<(&str, MapDims)> = LIFECYCLE_MAPS.to_vec();
    let bytes = build_lifecycle_fixture(
        &[
            "fentry/crypto_skcipher_encrypt",
            "fexit/crypto_skcipher_encrypt",
            "fentry/crypto_skcipher_decrypt",
        ],
        &maps,
    );
    let err = parse_lifecycle_object(&bytes).expect_err("missing fexit/decrypt must refuse");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("crypto_skcipher_decrypt"),
        "refusal names the site: {msg}"
    );
}

#[test]
fn h02_wrong_attach_prototype_refused() {
    let maps: Vec<(&str, MapDims)> = LIFECYCLE_MAPS.to_vec();
    let bytes = build_lifecycle_fixture(
        &[
            "fentry/crypto_skcipher_encrypt",
            "fexit/crypto_skcipher_encrypt",
            "fentry/crypto_skcipher_decrypt",
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
            "fentry/crypto_skcipher_encrypt",
            "fexit/crypto_skcipher_encrypt",
            "fentry/crypto_skcipher_decrypt",
            "fexit/crypto_skcipher_decrypt",
        ],
        &maps,
    );
    assert!(matches!(
        parse_lifecycle_object(&bytes),
        Err(LoaderError::UnsupportedMap { .. })
    ));
}

#[test]
fn h02_bad_dims_refused() {
    let mut maps: Vec<(&str, MapDims)> = LIFECYCLE_MAPS.to_vec();
    maps[0].1.value_size = 128;
    let bytes = build_lifecycle_fixture(
        &[
            "fentry/crypto_skcipher_encrypt",
            "fexit/crypto_skcipher_encrypt",
            "fentry/crypto_skcipher_decrypt",
            "fexit/crypto_skcipher_decrypt",
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
            "fentry/crypto_skcipher_encrypt",
            "fexit/crypto_skcipher_encrypt",
            "fentry/crypto_skcipher_decrypt",
            "fexit/crypto_skcipher_decrypt",
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
            "fentry/crypto_skcipher_encrypt",
            "fexit/crypto_skcipher_encrypt",
            "fentry/crypto_skcipher_decrypt",
            "fexit/crypto_skcipher_decrypt",
            "fentry/crypto_skcipher_extra",
        ],
        &maps,
    );
    let err = parse_lifecycle_object(&bytes).expect_err("5th program must refuse");
    let msg = format!("{err:?}");
    assert!(msg.contains('4'), "refusal names the manifest limit: {msg}");
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
            "fentry/crypto_skcipher_decrypt",
            "fentry/crypto_skcipher_encrypt",
            "fexit/crypto_skcipher_decrypt",
            "fexit/crypto_skcipher_encrypt",
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
fn bringup_resolve_finds_manifest_symbols() {
    // Profile-scoped resolution: exactly the manifest's symbols, no
    // more (unprivileged read; honest skip without host BTF).
    if std::fs::metadata("/sys/kernel/btf/vmlinux").is_err() {
        println!("SKIP: no /sys/kernel/btf/vmlinux on this host");
        return;
    }
    let ids = resolve_lifecycle_ids().expect("manifest symbols must resolve");
    assert_eq!(ids.len(), 2);
    assert!(ids.contains_key("crypto_skcipher_encrypt"));
    assert!(ids.contains_key("crypto_skcipher_decrypt"));
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
        loaded("fentry/crypto_skcipher_encrypt"),
        loaded("fexit/crypto_skcipher_encrypt"),
        loaded("fentry/crypto_skcipher_decrypt"),
        loaded("fexit/crypto_skcipher_decrypt"),
    ];
    let refs: Vec<(&str, &PointStatus)> = all.iter().map(|(s, st)| (s.as_str(), st)).collect();
    assert!(missing_required_points(&refs).is_empty());
    // One edge missing → named.
    let refs: Vec<(&str, &PointStatus)> = refs[..3].to_vec();
    assert_eq!(
        missing_required_points(&refs),
        ["fexit/crypto_skcipher_decrypt"]
    );
    // Unsupported counts as missing (refused load ≠ loaded point).
    let bad = [
        loaded("fentry/crypto_skcipher_encrypt"),
        loaded("fexit/crypto_skcipher_encrypt"),
        loaded("fentry/crypto_skcipher_decrypt"),
        missing("fexit/crypto_skcipher_decrypt"),
    ];
    let refs: Vec<(&str, &PointStatus)> = bad.iter().map(|(s, st)| (s.as_str(), st)).collect();
    assert_eq!(
        missing_required_points(&refs),
        ["fexit/crypto_skcipher_decrypt"]
    );
}

#[test]
fn bringup_config_bytes_carry_exact_magic_version() {
    // The 64 bytes the loader writes to LCFG key 0: magic + version +
    // zero flags/reserved — the exact words the BPF gate checks.
    let bytes = lifecycle_config_bytes();
    assert_eq!(bytes.len(), 64);
    assert_eq!(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        0x3143_4c4b
    );
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 1);
    assert!(bytes[8..].iter().all(|b| *b == 0));
}

#[test]
fn h02_api_returns_shape_rejected_by_lifecycle_parse() {
    // Cross-discrimination: an fexit-only api-returns-shaped object is
    // not a lifecycle object (missing entry edges + wrong map table).
    let bytes = build_lifecycle_fixture(
        &["fexit/crypto_alloc_tfm_node", "fexit/crypto_destroy_tfm"],
        LIFECYCLE_MAPS,
    );
    let err = parse_lifecycle_object(&bytes).expect_err("api-returns shape must refuse");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("crypto_skcipher_encrypt") || msg.contains("crypto_skcipher_decrypt"),
        "refusal names a missing required site: {msg}"
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

/// Minimal vmlinux-shaped BTF with the two lifecycle FUNCs. The
/// decrypt proto is always well-formed
/// (`int (struct skcipher_request *)`); the encrypt side takes the
/// given (return id, param-0 id, nargs, func-target id, pointee id,
/// INT data word, INT size) so refusal shapes are fixture-exact.
/// Type ids: 1 INT int, 2 STRUCT skcipher_request, 3 PTR→pointee, 4
/// encrypt FUNC_PROTO, 5 encrypt FUNC, 6 decrypt FUNC_PROTO, 7
/// decrypt FUNC, 8 STRUCT other_struct (wrong-pointee control), 9
/// PTR→2 (decrypt's own pointer, so encrypt-side pointee mutations
/// never break the decrypt control).
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
    btf_image(&types, &strtab)
}

/// Well-formed encrypt side: `int (struct skcipher_request *)` —
/// signed 32-bit INT (offset 0), PTR→STRUCT skcipher_request.
fn lifecycle_btf_good() -> Vec<u8> {
    lifecycle_btf(1, 3, 1, 4, 2, 0x0100_0020, 4)
}

#[test]
fn f2_wellformed_protos_resolve_both_ids() {
    // Control: int (struct skcipher_request *) on both sites resolves.
    let ids = resolve_lifecycle_ids_from(&lifecycle_btf_good()).expect("good protos");
    assert_eq!(ids.len(), 2);
    assert_eq!(ids["crypto_skcipher_encrypt"], 5);
    assert_eq!(ids["crypto_skcipher_decrypt"], 7);
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
    let ids = resolve_lifecycle_ids_from(&btf_image(&types, &strtab)).expect("chased proto");
    assert_eq!(ids.len(), 2);
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
    // same process and vice versa. Same-profile holders share (today's
    // aggregate concurrency is unchanged); dropping every holder
    // releases the process for the other profile. Single test: the
    // guard is process-global, so the sequence must not interleave.
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
    drop(life);
    assert!(acquire_kcrypto_session(LifecycleProfile::ApiReturns).is_ok());
}
