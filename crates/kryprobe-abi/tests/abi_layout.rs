// SPDX-License-Identifier: GPL-3.0-or-later
//! Frozen wire-layout asserts and `split_header` validation tests.

use kryprobe_abi::{
    ABI_VERSION, AbiError, BACKEND_OPENSSL, BACKEND_P11, BACKEND_SYNTHETIC, RawEventHeader,
    SpineEvent,
};
use kryprobe_abi::{BACKEND_KCRYPTO, EVENT_BARRIER, EVENT_LOSS, EVENT_OBSERVATION};

#[test]
fn header_size_and_align_are_frozen() {
    assert_eq!(std::mem::size_of::<RawEventHeader>(), 56);
    assert_eq!(std::mem::align_of::<RawEventHeader>(), 8);
}

#[test]
fn spine_event_size_and_align_are_frozen() {
    assert_eq!(std::mem::size_of::<SpineEvent>(), 64);
    assert_eq!(std::mem::align_of::<SpineEvent>(), 8);
}

#[test]
fn wire_id_consts_match_contracts() {
    assert_eq!(ABI_VERSION, 0);
    assert_eq!(BACKEND_P11, 1);
    assert_eq!(BACKEND_OPENSSL, 2);
    assert_eq!(BACKEND_KCRYPTO, 3);
    assert_eq!(BACKEND_SYNTHETIC, 0xFF);
    assert_eq!(EVENT_OBSERVATION, 1);
    assert_eq!(EVENT_LOSS, 2);
    assert_eq!(EVENT_BARRIER, 3);
}

/// 8-aligned scratch so `split_header` borrows pass its alignment check.
#[repr(C, align(8))]
struct AlignedBuf([u8; 256]);

fn header_bytes(header: &RawEventHeader) -> [u8; 56] {
    let mut out = [0u8; 56];
    // SAFETY: `RawEventHeader` is `#[repr(C)]`, 56 bytes, plain integers.
    let src: &[u8] = unsafe {
        std::slice::from_raw_parts(
            std::ptr::from_ref(header).cast::<u8>(),
            std::mem::size_of::<RawEventHeader>(),
        )
    };
    out.copy_from_slice(src);
    out
}

fn valid_header() -> RawEventHeader {
    RawEventHeader {
        abi_version: ABI_VERSION,
        backend_id: BACKEND_P11,
        event_kind: EVENT_OBSERVATION,
        flags: 0,
        total_len: 56,
        cpu: 0,
        session_cookie: 0xA5A5,
        monotonic_ns: 1,
        tgid: 7,
        tid: 8,
        process_generation: 1,
        plan_generation: 1,
        reserved: 0,
    }
}

/// Copies `header` + `payload` into 8-aligned storage, runs `f` on the record.
fn with_record<R>(
    header: &RawEventHeader,
    payload: &[u8],
    extra: &[u8],
    f: impl Fn(&[u8]) -> R,
) -> R {
    let mut buf = AlignedBuf([0u8; 256]);
    let hb = header_bytes(header);
    let total = hb.len() + payload.len() + extra.len();
    buf.0[..hb.len()].copy_from_slice(&hb);
    buf.0[hb.len()..hb.len() + payload.len()].copy_from_slice(payload);
    buf.0[hb.len() + payload.len()..total].copy_from_slice(extra);
    f(&buf.0[..total])
}

#[test]
fn split_header_ok_returns_header_and_payload() {
    let mut header = valid_header();
    header.total_len = 60;
    let payload = [9u8, 8, 7, 6];
    with_record(&header, &payload, &[], |bytes| {
        let (got, body) = kryprobe_abi::split_header(bytes).expect("valid record splits");
        assert_eq!(got.session_cookie, 0xA5A5);
        assert_eq!(got.total_len, 60);
        assert_eq!(body, &payload);
    });
}

#[test]
fn split_header_short_buffer_is_truncated() {
    let err = kryprobe_abi::split_header(&[0u8; 10]).expect_err("10-byte buffer must fail");
    assert_eq!(
        err,
        AbiError::Truncated {
            expected: 56,
            actual: 10
        }
    );
}

#[test]
fn split_header_total_len_mismatch() {
    let mut header = valid_header();
    header.total_len = 100;
    with_record(&header, &[], &[], |bytes| {
        let err = kryprobe_abi::split_header(bytes).expect_err("total_len 100 > 56 must fail");
        assert_eq!(
            err,
            AbiError::LengthMismatch {
                total_len: 100,
                buffer_len: 56
            }
        );
    });
}

#[test]
fn split_header_impossible_total_len_is_mismatch() {
    let mut header = valid_header();
    header.total_len = 4;
    with_record(&header, &[], &[0u8; 60], |bytes| {
        let err = kryprobe_abi::split_header(bytes).expect_err("total_len 4 must fail");
        assert_eq!(
            err,
            AbiError::LengthMismatch {
                total_len: 4,
                buffer_len: 116
            }
        );
    });
}

#[test]
fn split_header_unknown_version() {
    let mut header = valid_header();
    header.abi_version = 0xFFFF;
    with_record(&header, &[], &[], |bytes| {
        let err = kryprobe_abi::split_header(bytes).expect_err("bad version must fail");
        assert_eq!(err, AbiError::UnknownVersion { version: 0xFFFF });
    });
}

#[test]
fn split_header_misaligned_buffer_is_rejected() {
    // Valid record shifted one byte into 8-aligned storage: the bytes
    // decode fine, but the address is misaligned. Must be a checked
    // error, never UB (the old debug_assert compiled out in release).
    let header = valid_header();
    let hb = header_bytes(&header);
    let mut buf = AlignedBuf([0u8; 256]);
    buf.0[1..1 + hb.len()].copy_from_slice(&hb);
    let bytes = &buf.0[1..1 + hb.len()];
    assert_ne!(
        bytes.as_ptr() as usize % 8,
        0,
        "test setup must misalign the buffer"
    );
    let err = kryprobe_abi::split_header(bytes).expect_err("misaligned buffer must fail");
    assert_eq!(
        err,
        AbiError::Misaligned {
            addr: bytes.as_ptr() as usize,
            align: 8,
        }
    );
}

#[test]
fn split_header_trailing_bytes() {
    let header = valid_header();
    with_record(&header, &[], &[0u8; 8], |bytes| {
        let err = kryprobe_abi::split_header(bytes).expect_err("64-byte buffer, len 56 must fail");
        assert_eq!(
            err,
            AbiError::TrailingBytes {
                total_len: 56,
                buffer_len: 64
            }
        );
    });
}
