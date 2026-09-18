// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw loader tests: pure parse asserts + honest unprivileged facet load.
//!
//! Parse tests never touch syscalls; the load test passes both
//! unprivileged (honest EPERM/EACCES surfaced) and privileged (real fds).

use kryprobe_core::ProgramId;
use kryprobe_core::authority::BpfLoadAuthority;
use kryprobe_privilege::LocalPrivilegedAuthority;
use kryprobe_privilege::bpfloader::{
    LoaderError, MapDims, SPINE_MAPS, check_record_align, parse_spine_object,
};
use std::path::PathBuf;

fn spine_object_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("kryprobe-bpf")
        .join("spine.bpf.o")
}

fn object_bytes() -> Vec<u8> {
    let path = spine_object_path();
    assert!(
        path.is_file(),
        "missing BPF spine object at {} — run `cargo xtask build --bpf`",
        path.display()
    );
    std::fs::read(&path).expect("test fixture must be readable")
}

#[test]
fn parse_reports_frozen_dims() {
    let bytes = object_bytes();
    let parsed = parse_spine_object(&bytes).expect("real object must parse");
    assert_eq!(parsed.maps.len(), SPINE_MAPS.len(), "map count drifted");
    for ((want_name, want_dims), got) in SPINE_MAPS.iter().zip(parsed.maps.iter()) {
        assert_eq!(got.name, *want_name);
        assert_eq!(got.dims, *want_dims, "dims drifted for {want_name}");
    }
    assert_eq!(parsed.maps.len(), 5);
}

#[test]
fn parse_finds_both_programs() {
    let bytes = object_bytes();
    let parsed = parse_spine_object(&bytes).expect("real object must parse");
    let names: Vec<&str> = parsed.programs.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["spine_selftest", "spine_selftest_ret"]);
    for prog in &parsed.programs {
        assert!(!prog.insns.is_empty(), "{} has no insns", prog.name);
    }
}

#[test]
fn parse_resolves_calls_and_plans_map_fixups() {
    let bytes = object_bytes();
    let parsed = parse_spine_object(&bytes).expect("real object must parse");
    // 10 map references across .text (START×1 CONFIG×2 COUNT×1 EVENTS×1
    // LOSS×5 incl. the disarmed-drop and wide-CONFIG-refusal bumps),
    // applied to each program stream.
    assert_eq!(parsed.map_relocs.len(), 20);
    for prog in 0..2 {
        let per_prog = parsed.map_relocs.iter().filter(|r| r.prog == prog).count();
        assert_eq!(per_prog, 10, "program {prog} fixup count drifted");
    }
    for reloc in &parsed.map_relocs {
        assert!(parsed.maps.iter().any(|m| m.name == reloc.map));
    }
    // No BPF_PSEUDO_CALL (-1) placeholder survives the parse, and every
    // subprogram call (src nibble set; plain helper calls excluded) lands
    // on an insn inside its own stream.
    for prog in &parsed.programs {
        for (i, insn) in prog.insns.iter().enumerate() {
            if insn.code == 0x85 {
                assert_ne!(insn.imm, -1, "{}: call at {i} left unresolved", prog.name);
                if insn.dst_src & 0xf0 == 0 {
                    continue; // helper call: imm is a helper id, not a target
                }
                let target = i as i64 + 1 + insn.imm as i64;
                assert!(
                    target >= 0 && (target as usize) < prog.insns.len(),
                    "{}: call at {i} targets {target} (len {})",
                    prog.name,
                    prog.insns.len()
                );
            }
        }
    }
}

#[test]
fn frozen_dims_match_object() {
    // SPINE_MAPS pins the T7b dims; the object is ground truth.
    let want = [
        (
            "CONFIG",
            MapDims {
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 2,
            },
        ),
        (
            "START",
            MapDims {
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
            },
        ),
        (
            "COUNT",
            MapDims {
                map_type: 6,
                key_size: 4,
                value_size: 8,
                max_entries: 64,
            },
        ),
        (
            "EVENTS",
            MapDims {
                map_type: 27,
                key_size: 0,
                value_size: 0,
                max_entries: 262_144,
            },
        ),
        (
            "LOSS",
            MapDims {
                map_type: 6,
                key_size: 4,
                value_size: 8,
                max_entries: 3,
            },
        ),
    ];
    assert_eq!(SPINE_MAPS.len(), want.len());
    for ((name, dims), (wname, wdims)) in SPINE_MAPS.iter().zip(want.iter()) {
        assert_eq!(name, wname);
        assert_eq!(dims, wdims);
    }
}

#[test]
fn corrupt_object_rejected() {
    assert!(matches!(
        parse_spine_object(b"not an elf file at all...................."),
        Err(LoaderError::BadObject { .. })
    ));
    assert!(matches!(
        parse_spine_object(&[]),
        Err(LoaderError::BadObject { .. })
    ));
}

#[test]
fn instantiate_degrades_honestly() {
    let bytes = object_bytes();
    match LocalPrivilegedAuthority.load_program(ProgramId::UprobeMultiSelfProbe, &bytes) {
        Ok(loaded) => {
            // Privileged path: real fds, all valid.
            for fd in [
                loaded.maps.config.as_raw_fd(),
                loaded.maps.start.as_raw_fd(),
                loaded.maps.count.as_raw_fd(),
                loaded.maps.events.as_raw_fd(),
                loaded.maps.loss.as_raw_fd(),
                loaded.progs.entry.as_raw_fd(),
                loaded.progs.ret.as_raw_fd(),
            ] {
                assert!(fd >= 0, "privileged instantiate gave invalid fd");
            }
        }
        Err(LoaderError::MapFailed { errno, .. }) | Err(LoaderError::LoadFailed { errno, .. }) => {
            assert!(
                errno == libc::EPERM || errno == libc::EACCES,
                "unprivileged instantiate must surface EPERM/EACCES, got {errno}"
            );
        }
        Err(other) => panic!("instantiate failed dishonestly: {other}"),
    }
}

#[test]
fn misaligned_record_rejected() {
    let aligned = [0u8; 64];
    assert!(check_record_align(&aligned).is_ok());
    assert!(check_record_align(&aligned[1..]).is_err());
    assert!(matches!(
        check_record_align(&aligned[1..]),
        Err(LoaderError::MisalignedRecord { .. })
    ));
}

/// File offset of the `entry`-th `Elf64_Rel` in `section` (16 bytes each).
fn reloc_entry_offset(bytes: &[u8], section: &str, entry: usize) -> usize {
    let elf = goblin::elf::Elf::parse(bytes).expect("fixture must be a valid ELF");
    let sh = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(section))
        .unwrap_or_else(|| panic!("missing section '{section}'"));
    assert_eq!(sh.sh_type, 9, "{section} must be SHT_REL");
    sh.sh_offset as usize + entry * 16
}

/// File offset of the `r_offset` field of the first reloc of `rel_type`.
fn first_reloc_offset_of_type(bytes: &[u8], rel_type: u32) -> usize {
    let elf = goblin::elf::Elf::parse(bytes).expect("fixture must be a valid ELF");
    for sh in elf.section_headers.iter() {
        if sh.sh_type != 9 {
            continue;
        }
        let base = sh.sh_offset as usize;
        let count = sh.sh_size as usize / 16;
        for entry in 0..count {
            let at = base + entry * 16;
            let info = u64::from_le_bytes(bytes[at + 8..at + 16].try_into().expect("rel entry"));
            if (info & 0xffff_ffff) as u32 == rel_type {
                return at;
            }
        }
    }
    panic!("no reloc of type {rel_type} in fixture");
}

fn patch_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// File offset of the `st_value` field of the section symbol that the
/// first `R_BPF_64_32` reloc references (nameless: found via `r_info`).
fn call_sym_value_offset(bytes: &[u8]) -> usize {
    let elf = goblin::elf::Elf::parse(bytes).expect("fixture must be a valid ELF");
    let mut sym_idx = None;
    for sh in elf.section_headers.iter() {
        if sh.sh_type != 9 {
            continue;
        }
        let base = sh.sh_offset as usize;
        for entry in 0..sh.sh_size as usize / 16 {
            let at = base + entry * 16;
            let info = u64::from_le_bytes(bytes[at + 8..at + 16].try_into().expect("rel entry"));
            if (info & 0xffff_ffff) as u32 == 10 {
                sym_idx = Some((info >> 32) as usize);
                break;
            }
        }
    }
    let sym_idx = sym_idx.expect("fixture must contain call relocs");
    let symtab = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".symtab"))
        .expect("fixture must have a symtab");
    symtab.sh_offset as usize + sym_idx * 24 + 8
}

/// Set the `imm` of every `R_BPF_64_32` target insn (call sites carry -1
/// from LLVM; the addend path needs a non-negative value to overflow).
fn patch_call_target_imms(bytes: &mut [u8], imm: i32) {
    // Collect patch sites first: `Elf` borrows `bytes` immutably.
    let sites: Vec<usize> = {
        let elf = goblin::elf::Elf::parse(bytes).expect("fixture must be a valid ELF");
        let mut sites = Vec::new();
        for sh in elf.section_headers.iter() {
            if sh.sh_type != 9 {
                continue;
            }
            let target_base = elf.section_headers[sh.sh_info as usize].sh_offset as usize;
            let base = sh.sh_offset as usize;
            for entry in 0..sh.sh_size as usize / 16 {
                let at = base + entry * 16;
                let info =
                    u64::from_le_bytes(bytes[at + 8..at + 16].try_into().expect("rel entry"));
                if (info & 0xffff_ffff) as u32 != 10 {
                    continue;
                }
                let offset = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("rel offset"));
                sites.push(target_base + offset as usize + 4);
            }
        }
        sites
    };
    assert!(!sites.is_empty(), "fixture must contain call relocs");
    for imm_at in sites {
        bytes[imm_at..imm_at + 4].copy_from_slice(&imm.to_le_bytes());
    }
}

fn assert_bad_object(bytes: &[u8], what: &str) {
    match parse_spine_object(bytes) {
        Err(LoaderError::BadObject { .. }) => {}
        Err(other) => panic!("{what} must be BadObject, got {other}"),
        Ok(_) => panic!("{what} must be BadObject, parsed clean"),
    }
}

/// Largest 8-aligned `r_offset`: a wrap candidate near the top of the
/// index range (`usize::MAX & !7` on 64-bit).
const HUGE_ALIGNED_OFFSET: u64 = !7;

#[test]
fn reloc_huge_map_offset_is_bad_object() {
    let mut bytes = object_bytes();
    let at = first_reloc_offset_of_type(&bytes, 1);
    patch_u64(&mut bytes, at, HUGE_ALIGNED_OFFSET);
    assert_bad_object(&bytes, "huge map reloc offset");
}

#[test]
fn reloc_huge_call_offset_is_bad_object() {
    let mut bytes = object_bytes();
    let at = first_reloc_offset_of_type(&bytes, 10);
    patch_u64(&mut bytes, at, HUGE_ALIGNED_OFFSET);
    assert_bad_object(&bytes, "huge call reloc offset");
}

#[test]
fn reloc_misaligned_offset_is_bad_object() {
    let mut bytes = object_bytes();
    let at = reloc_entry_offset(&bytes, ".rel.text", 0);
    patch_u64(&mut bytes, at, 4);
    assert_bad_object(&bytes, "misaligned reloc offset");
}

#[test]
fn reloc_call_target_overflow_is_bad_object() {
    // `st_value (i64::MAX) + imm (1)` overflows i64: BadObject, never panic.
    let mut bytes = object_bytes();
    let value_at = call_sym_value_offset(&bytes);
    patch_u64(&mut bytes, value_at, i64::MAX as u64);
    patch_call_target_imms(&mut bytes, 1);
    assert_bad_object(&bytes, "overflowing call reloc target");
}

#[test]
fn parse_hostile_inputs_fail_closed() {
    // Empty, truncated, and non-ELF inputs: graceful errors, never panic.
    assert!(parse_spine_object(&[]).is_err());
    assert!(parse_spine_object(&[0x7f, b'E', b'L']).is_err());
    assert!(parse_spine_object(&[b'X'; 64]).is_err());
    // Minimal ELF header, no sections: missing .text, not a crash.
    let mut hdr = vec![0u8; 64];
    hdr[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    hdr[4] = 2;
    hdr[5] = 1;
    hdr[6] = 1;
    hdr[18..20].copy_from_slice(&247u16.to_le_bytes());
    hdr[52..54].copy_from_slice(&64u16.to_le_bytes());
    let err = parse_spine_object(&hdr).unwrap_err();
    assert!(
        matches!(err, LoaderError::BadObject { .. }),
        "hostile header must be BadObject, got {err}"
    );
}
