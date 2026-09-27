// SPDX-License-Identifier: GPL-3.0-or-later
//! T06 lifecycle ABI layout pins: userspace mirrors of the BPF-side
//! structs (twin: `crates/bpf-kcrypto/src/bin/kcrypto_lifecycle.rs`).
//! Any drift between BPF bytes and these mirrors must fail here.

use kryprobe_abi::kcrypto_lifecycle::{
    LAGG_AEADDEC_RET, LAGG_AEADDEC_SUB, LAGG_AEADENC_RET, LAGG_AEADENC_SUB, LAGG_ALLOCAEAD_RET,
    LAGG_ALLOCAEAD_SUB, LAGG_ALLOCSK_RET, LAGG_ALLOCSK_SUB, LAGG_CB_CRYPTD, LAGG_CB_KXC,
    LAGG_DEC_RET, LAGG_DEC_SUB, LAGG_DESTROY_RET, LAGG_DESTROY_SUB, LAGG_ENC_RET, LAGG_ENC_SUB,
    LAGG_SETAUTH_RET, LAGG_SETAUTH_SUB, LAGG_SETKEYAEAD_RET, LAGG_SETKEYAEAD_SUB,
    LAGG_SETKEYSK_RET, LAGG_SETKEYSK_SUB, LCONFIG_MAGIC, LCONFIG_VERSION, LConfig, LDIR_DEC,
    LDIR_ENC, LEDGE_INVOC_POISON, LEDGE_MAGIC, LEDGE_RETURN, LEDGE_SUBMIT, LEDGE_TAINTED,
    LEDGE_VERSION, LEdge, LFAM_AEAD, LFAM_SK, LLOSS_BADKEY, LLOSS_DISABLED, LLOSS_FRET,
    LLOSS_NOSLOT, LLOSS_RESERVE, LMETA_ASSOCLEN_OK, LMETA_AUTHSIZE_OK, LMETA_CRYPTLEN_OK,
    LMETA_REQFLAGS_OK, LSITE_AEAD_DEC, LSITE_AEAD_ENC, LSITE_DEC, LSITE_ENC, LTFM_MAGIC,
    LTFM_SITE_ALLOC_AEAD, LTFM_SITE_ALLOC_SK, LTFM_SITE_DESTROY, LTFM_SITE_SETAUTHSIZE,
    LTFM_SITE_SETKEY_AEAD, LTFM_SITE_SETKEY_SK, LTFM_TRUNCATED, LTFM_VERSION, LTfm,
};
use std::mem::{offset_of, size_of};

#[test]
fn ledge_is_112_bytes_with_pinned_offsets() {
    assert_eq!(size_of::<LEdge>(), 112);
    assert_eq!(offset_of!(LEdge, magic), 0);
    assert_eq!(offset_of!(LEdge, version), 2);
    assert_eq!(offset_of!(LEdge, edge), 3);
    assert_eq!(offset_of!(LEdge, site), 4);
    assert_eq!(offset_of!(LEdge, flags), 6);
    assert_eq!(offset_of!(LEdge, key), 8);
    assert_eq!(offset_of!(LEdge, ts_ns), 16);
    assert_eq!(offset_of!(LEdge, status), 24);
    assert_eq!(offset_of!(LEdge, cryptlen), 28);
    assert_eq!(offset_of!(LEdge, invoc), 32);
    assert_eq!(offset_of!(LEdge, tfm), 40);
    assert_eq!(offset_of!(LEdge, req_flags), 48);
    assert_eq!(offset_of!(LEdge, fam), 52);
    assert_eq!(offset_of!(LEdge, dir), 53);
    assert_eq!(offset_of!(LEdge, mflags), 54);
    assert_eq!(offset_of!(LEdge, assoclen), 56);
    assert_eq!(offset_of!(LEdge, authsize), 60);
    assert_eq!(offset_of!(LEdge, drv), 64);
}

#[test]
fn ledge_enum_values_are_frozen() {
    assert_eq!(LEDGE_MAGIC, 0x434c);
    assert_eq!(LEDGE_VERSION, 7);
    assert_eq!(LEDGE_INVOC_POISON, 1);
    assert_eq!(LEDGE_SUBMIT, 1);
    assert_eq!(LEDGE_RETURN, 2);
    assert_eq!(LEDGE_TAINTED, 0x0001);
    assert_eq!(LSITE_ENC, 1);
    assert_eq!(LSITE_DEC, 2);
    assert_eq!(LSITE_AEAD_ENC, 5);
    assert_eq!(LSITE_AEAD_DEC, 6);
    assert_eq!(LFAM_SK, 1);
    assert_eq!(LFAM_AEAD, 2);
    assert_eq!(LDIR_ENC, 1);
    assert_eq!(LDIR_DEC, 2);
    assert_eq!(LMETA_CRYPTLEN_OK, 0x0001);
    assert_eq!(LMETA_REQFLAGS_OK, 0x0002);
    assert_eq!(LMETA_ASSOCLEN_OK, 0x0004);
    assert_eq!(LMETA_AUTHSIZE_OK, 0x0008);
}

#[test]
fn ltfm_is_112_bytes_with_pinned_offsets() {
    assert_eq!(size_of::<LTfm>(), 112);
    assert_eq!(offset_of!(LTfm, magic), 0);
    assert_eq!(offset_of!(LTfm, version), 2);
    assert_eq!(offset_of!(LTfm, edge), 3);
    assert_eq!(offset_of!(LTfm, site), 4);
    assert_eq!(offset_of!(LTfm, flags), 6);
    assert_eq!(offset_of!(LTfm, key), 8);
    assert_eq!(offset_of!(LTfm, ts_ns), 16);
    assert_eq!(offset_of!(LTfm, status), 24);
    assert_eq!(offset_of!(LTfm, aux), 28);
    assert_eq!(offset_of!(LTfm, aux2), 32);
    assert_eq!(offset_of!(LTfm, token), 40);
    assert_eq!(offset_of!(LTfm, name), 48);
    // The 4-byte alignment pad (36..40) is BPF-zeroed reserved
    // storage: the emitter writes it per record (D2 — ring memory
    // is uninitialized, so an unnamed gap would carry stale bytes).
    assert_eq!(offset_of!(LTfm, token) - (offset_of!(LTfm, aux2) + 4), 4);
}

#[test]
fn ltfm_enum_values_are_frozen() {
    assert_eq!(LTFM_MAGIC, 0x544c);
    assert_eq!(LTFM_VERSION, 1);
    assert_eq!(LTFM_TRUNCATED, 0x0002);
    assert_eq!(LTFM_SITE_ALLOC_SK, 1);
    assert_eq!(LTFM_SITE_DESTROY, 2);
    assert_eq!(LTFM_SITE_SETKEY_SK, 3);
    assert_eq!(LTFM_SITE_SETAUTHSIZE, 4);
    assert_eq!(LTFM_SITE_ALLOC_AEAD, 5);
    assert_eq!(LTFM_SITE_SETKEY_AEAD, 6);
}

#[test]
fn ltfm_debug_redacts_kernel_key_but_shows_name() {
    // Same promise as `LEdge`: the raw kernel pointer redacts;
    // the algorithm name is public inventory and renders.
    let mut tfm = LTfm {
        magic: LTFM_MAGIC,
        version: LTFM_VERSION,
        edge: LEDGE_SUBMIT,
        site: LTFM_SITE_ALLOC_SK,
        flags: 0,
        key: 0xdead_beef_1234_5678,
        ts_ns: 7,
        status: 0,
        aux: 0,
        aux2: 0,
        token: 42,
        name: [0; 64],
    };
    tfm.name[..8].copy_from_slice(b"kxcipher");
    let shown = format!("{tfm:?}");
    assert!(shown.contains("<redacted>"), "{shown}");
    assert!(shown.contains("42"), "{shown}");
    assert!(!shown.contains("dead"), "{shown}");
    assert!(
        !shown.contains(&0xdead_beef_1234_5678u64.to_string()),
        "{shown}"
    );
}

#[test]
fn lconfig_is_80_bytes_with_pinned_offsets() {
    assert_eq!(size_of::<LConfig>(), 80);
    assert_eq!(offset_of!(LConfig, magic), 0);
    assert_eq!(offset_of!(LConfig, version), 4);
    assert_eq!(offset_of!(LConfig, flags), 8);
    assert_eq!(offset_of!(LConfig, tfm_alg), 12);
    assert_eq!(offset_of!(LConfig, alg_drv), 16);
    assert_eq!(offset_of!(LConfig, sk_base), 20);
    assert_eq!(offset_of!(LConfig, refcnt_off), 24);
    assert_eq!(offset_of!(LConfig, refcnt_present), 28);
    assert_eq!(offset_of!(LConfig, req_base), 32);
    assert_eq!(offset_of!(LConfig, req_tfm), 36);
    assert_eq!(offset_of!(LConfig, req_cryptlen), 40);
    assert_eq!(offset_of!(LConfig, req_flags), 44);
    assert_eq!(offset_of!(LConfig, op_req_off), 48);
    assert_eq!(offset_of!(LConfig, op_req_present), 52);
    assert_eq!(offset_of!(LConfig, aead_req_base), 56);
    assert_eq!(offset_of!(LConfig, aead_req_cryptlen), 60);
    assert_eq!(offset_of!(LConfig, aead_req_assoclen), 64);
    assert_eq!(offset_of!(LConfig, aead_base), 68);
    assert_eq!(offset_of!(LConfig, aead_authsize), 72);
    assert_eq!(offset_of!(LConfig, reserved), 76);
}

#[test]
fn lconfig_magic_version_are_frozen() {
    assert_eq!(LCONFIG_MAGIC, 0x3143_4c4b);
    assert_eq!(LCONFIG_VERSION, 6);
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
    // (op hooks 0-3 frozen; T07 transform hooks 4-15).
    assert_eq!(LAGG_ENC_SUB, 0);
    assert_eq!(LAGG_ENC_RET, 1);
    assert_eq!(LAGG_DEC_SUB, 2);
    assert_eq!(LAGG_DEC_RET, 3);
    assert_eq!(LAGG_ALLOCSK_SUB, 4);
    assert_eq!(LAGG_ALLOCSK_RET, 5);
    assert_eq!(LAGG_DESTROY_SUB, 6);
    assert_eq!(LAGG_DESTROY_RET, 7);
    assert_eq!(LAGG_SETKEYSK_SUB, 8);
    assert_eq!(LAGG_SETKEYSK_RET, 9);
    assert_eq!(LAGG_SETAUTH_SUB, 10);
    assert_eq!(LAGG_SETAUTH_RET, 11);
    assert_eq!(LAGG_ALLOCAEAD_SUB, 12);
    assert_eq!(LAGG_ALLOCAEAD_RET, 13);
    assert_eq!(LAGG_SETKEYAEAD_SUB, 14);
    assert_eq!(LAGG_SETKEYAEAD_RET, 15);
    assert_eq!(LAGG_CB_CRYPTD, 16);
    assert_eq!(LAGG_CB_KXC, 17);
    assert_eq!(LAGG_AEADENC_SUB, 18);
    assert_eq!(LAGG_AEADENC_RET, 19);
    assert_eq!(LAGG_AEADDEC_SUB, 20);
    assert_eq!(LAGG_AEADDEC_RET, 21);
}

#[test]
fn f9_ledge_debug_redacts_kernel_key() {
    // Round-1 (sol-m9/astra-m9): the module promises no report, log,
    // or error string renders the raw kernel pointer. Debug is a log
    // surface: it must redact the key, not derive-print it.
    let mut edge = LEdge {
        magic: LEDGE_MAGIC,
        version: LEDGE_VERSION,
        edge: LEDGE_SUBMIT,
        site: LSITE_ENC,
        flags: 0,
        key: 0xdead_beef_1234_5678,
        ts_ns: 7,
        status: 0,
        cryptlen: 16,
        invoc: 41,
        tfm: 0xcafe_f00d_2468_1357,
        req_flags: 0,
        fam: LFAM_SK,
        dir: LDIR_ENC,
        mflags: LMETA_CRYPTLEN_OK,
        assoclen: 0,
        authsize: 0,
        drv: [0; 48],
    };
    edge.drv[..11].copy_from_slice(b"aes-generic");
    let shown = format!("{edge:?}");
    assert!(shown.contains("<redacted>"), "{shown}");
    assert!(
        shown.contains("41"),
        "invoc is a counter, not redacted: {shown}"
    );
    assert!(shown.contains("97"), "driver name renders: {shown}");
    // T07.3: `tfm` is a second raw kernel pointer — it redacts like
    // `key` (same no-render promise; Debug is a log surface).
    assert!(!shown.contains("dead"), "{shown}");
    assert!(!shown.contains("cafe"), "{shown}");
    assert!(
        !shown.contains(&0xdead_beef_1234_5678u64.to_string()),
        "{shown}"
    );
    assert!(
        !shown.contains(&0xcafe_f00d_2468_1357u64.to_string()),
        "{shown}"
    );
}
