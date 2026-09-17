// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw loader tests: pure parse asserts + honest unprivileged instantiate.
//!
//! Parse tests never touch syscalls; the instantiate test passes both
//! unprivileged (honest EPERM/EACCES surfaced) and privileged (real fds).

use kryprobe_privilege::bpfloader::{
    LoaderError, MapDims, SPINE_MAPS, check_record_align, instantiate, parse_spine_object,
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
    // 8 map references across .text (START×1 CONFIG×2 COUNT×1 EVENTS×1
    // LOSS×3), applied to each of the 2 program streams.
    assert_eq!(parsed.map_relocs.len(), 16);
    for prog in 0..2 {
        let per_prog = parsed.map_relocs.iter().filter(|r| r.prog == prog).count();
        assert_eq!(per_prog, 8, "program {prog} fixup count drifted");
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
                max_entries: 2,
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
    let parsed = parse_spine_object(&bytes).expect("real object must parse");
    match instantiate(&parsed) {
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
