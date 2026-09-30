// SPDX-License-Identifier: GPL-3.0-or-later
//! Roundtrip + rejection properties for the synthetic event codec.

use kryprobe_abi::{BACKEND_SYNTHETIC, EVENT_OBSERVATION, RawEventHeader};
use kryprobe_core::backend::RawEvent;
use kryprobe_core::enums::{CallKind, EvidencePhase, OperationClass};
use kryprobe_core::synthetic::codec::{decode_event, encode_event};
use proptest::prelude::*;

fn phase_strategy() -> impl Strategy<Value = EvidencePhase> {
    prop_oneof![
        Just(EvidencePhase::Discovered),
        Just(EvidencePhase::Selected),
        Just(EvidencePhase::Entered),
        Just(EvidencePhase::Returned),
        Just(EvidencePhase::Completed),
        Just(EvidencePhase::Succeeded),
    ]
}

fn class_strategy() -> impl Strategy<Value = OperationClass> {
    prop_oneof![
        Just(OperationClass::Sign),
        Just(OperationClass::Verify),
        Just(OperationClass::Encrypt),
        Just(OperationClass::Decrypt),
        Just(OperationClass::Digest),
        Just(OperationClass::Mac),
        Just(OperationClass::Kdf),
        Just(OperationClass::KeyAgreement),
        Just(OperationClass::KemEncapsulate),
        Just(OperationClass::KemDecapsulate),
        Just(OperationClass::Random),
        Just(OperationClass::KeyManagement),
        Just(OperationClass::Unknown),
    ]
}

fn call_strategy() -> impl Strategy<Value = CallKind> {
    prop_oneof![
        Just(CallKind::Operation),
        Just(CallKind::Initialization),
        Just(CallKind::SizeQuery),
        Just(CallKind::Update),
        Just(CallKind::Finalization),
        Just(CallKind::Unknown),
    ]
}

fn header() -> RawEventHeader {
    RawEventHeader {
        abi_version: kryprobe_abi::ABI_VERSION,
        backend_id: BACKEND_SYNTHETIC,
        event_kind: EVENT_OBSERVATION,
        flags: 0,
        total_len: 0,
        cpu: 0,
        session_cookie: 0,
        monotonic_ns: 0,
        tgid: 0,
        tid: 0,
        process_generation: 0,
        plan_generation: 0,
        reserved: 0,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// decode(encode(phase, class, call, code)) is the identity.
    #[test]
    fn codec_roundtrip(
        phase in phase_strategy(),
        class in class_strategy(),
        call in call_strategy(),
        code in any::<i32>(),
    ) {
        let payload = encode_event(phase, class, call, code);
        let event = RawEvent { header: header(), payload: &payload };
        prop_assert_eq!(decode_event(&event), Ok((phase, class, call, code)));
    }

    /// Out-of-table indices reject; in-table triples always accept.
    #[test]
    fn codec_accepts_exactly_the_tables(
        pi in any::<u8>(),
        ci in any::<u8>(),
        ki in any::<u8>(),
        code in any::<i32>(),
    ) {
        let mut payload = [0u8; 8];
        payload[1] = pi;
        payload[2] = ci;
        payload[3] = ki;
        payload[4..8].copy_from_slice(&code.to_le_bytes());
        let event = RawEvent { header: header(), payload: &payload };
        let valid = pi <= 5 && ci <= 12 && ki <= 5;
        prop_assert_eq!(decode_event(&event).is_ok(), valid);
    }
}
