// SPDX-License-Identifier: GPL-3.0-or-later
//! T06 lifecycle ABI layout pins: userspace mirrors of the BPF-side
//! structs (twin: `crates/bpf-kcrypto/src/bin/kcrypto_lifecycle.rs`).
//! Any drift between BPF bytes and these mirrors must fail here.

use kryprobe_abi::kcrypto_lifecycle::{
    LAGG_DEC_RET, LAGG_DEC_SUB, LAGG_ENC_RET, LAGG_ENC_SUB, LCONFIG_MAGIC, LCONFIG_VERSION,
    LConfig, LEDGE_MAGIC, LEDGE_RETURN, LEDGE_SUBMIT, LEDGE_TAINTED, LEDGE_VERSION, LEdge,
    LLOSS_BADKEY, LLOSS_DISABLED, LLOSS_FRET, LLOSS_NOSLOT, LLOSS_RESERVE, LSITE_DEC, LSITE_ENC,
};
use std::mem::{offset_of, size_of};

#[test]
fn ledge_is_40_bytes_with_pinned_offsets() {
    assert_eq!(size_of::<LEdge>(), 40);
    assert_eq!(offset_of!(LEdge, magic), 0);
    assert_eq!(offset_of!(LEdge, version), 2);
    assert_eq!(offset_of!(LEdge, edge), 3);
    assert_eq!(offset_of!(LEdge, site), 4);
    assert_eq!(offset_of!(LEdge, flags), 6);
    assert_eq!(offset_of!(LEdge, key), 8);
    assert_eq!(offset_of!(LEdge, ts_ns), 16);
    assert_eq!(offset_of!(LEdge, status), 24);
    assert_eq!(offset_of!(LEdge, aux), 28);
    assert_eq!(offset_of!(LEdge, invoc), 32);
}

#[test]
fn ledge_enum_values_are_frozen() {
    assert_eq!(LEDGE_MAGIC, 0x434c);
    assert_eq!(LEDGE_VERSION, 3);
    assert_eq!(LEDGE_SUBMIT, 1);
    assert_eq!(LEDGE_RETURN, 2);
    assert_eq!(LEDGE_TAINTED, 0x0001);
    assert_eq!(LSITE_ENC, 1);
    assert_eq!(LSITE_DEC, 2);
}

#[test]
fn lconfig_is_64_bytes_with_pinned_offsets() {
    assert_eq!(size_of::<LConfig>(), 64);
    assert_eq!(offset_of!(LConfig, magic), 0);
    assert_eq!(offset_of!(LConfig, version), 4);
    assert_eq!(offset_of!(LConfig, flags), 8);
    assert_eq!(offset_of!(LConfig, reserved), 12);
}

#[test]
fn lconfig_magic_version_are_frozen() {
    assert_eq!(LCONFIG_MAGIC, 0x3143_4c4b);
    assert_eq!(LCONFIG_VERSION, 1);
}

#[test]
fn lloss_class_indices_are_frozen() {
    assert_eq!(LLOSS_RESERVE, 0);
    assert_eq!(LLOSS_DISABLED, 1);
    assert_eq!(LLOSS_BADKEY, 2);
    assert_eq!(LLOSS_FRET, 3);
    assert_eq!(LLOSS_NOSLOT, 4);
}

#[test]
fn lagg_hook_indices_are_frozen() {
    // Per-hook accepted-edge order matches `edge_hits`
    // (enc-submit, enc-return, dec-submit, dec-return).
    assert_eq!(LAGG_ENC_SUB, 0);
    assert_eq!(LAGG_ENC_RET, 1);
    assert_eq!(LAGG_DEC_SUB, 2);
    assert_eq!(LAGG_DEC_RET, 3);
}

#[test]
fn f9_ledge_debug_redacts_kernel_key() {
    // Round-1 (sol-m9/astra-m9): the module promises no report, log,
    // or error string renders the raw kernel pointer. Debug is a log
    // surface: it must redact the key, not derive-print it.
    let edge = LEdge {
        magic: LEDGE_MAGIC,
        version: LEDGE_VERSION,
        edge: LEDGE_SUBMIT,
        site: LSITE_ENC,
        flags: 0,
        key: 0xdead_beef_1234_5678,
        ts_ns: 7,
        status: 0,
        aux: 0,
        invoc: 41,
    };
    let shown = format!("{edge:?}");
    assert!(shown.contains("<redacted>"), "{shown}");
    assert!(
        shown.contains("41"),
        "invoc is a counter, not redacted: {shown}"
    );
    assert!(!shown.contains("dead"), "{shown}");
    assert!(
        !shown.contains(&0xdead_beef_1234_5678u64.to_string()),
        "{shown}"
    );
}
