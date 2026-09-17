// SPDX-License-Identifier: GPL-3.0-or-later
//! Synthetic event codec: fixed 8-byte versioned payloads.
//!
//! Layout: `[version, phase, class, call, code:4 LE]`. Enum indices follow
//! declaration order. Anything outside the tables is [`BackendError::CorruptInput`].

use crate::backend::RawEvent;
use crate::enums::{CallKind, EvidencePhase, OperationClass};
use crate::error::{BackendError, InputReason};
use kryprobe_abi::{BACKEND_SYNTHETIC, EVENT_OBSERVATION};

/// Codec version stamped on every synthetic payload.
const CODEC_VERSION: u8 = 0;

/// Encode one scripted event payload; total over all inputs.
#[must_use]
pub fn encode_event(
    phase: EvidencePhase,
    class: OperationClass,
    call: CallKind,
    code: i32,
) -> [u8; 8] {
    let mut bytes = [0_u8; 8];
    bytes[0] = CODEC_VERSION;
    bytes[1] = phase_index(phase);
    bytes[2] = class_index(class);
    bytes[3] = call_index(call);
    bytes[4..8].copy_from_slice(&code.to_le_bytes());
    bytes
}

/// Decode and validate one raw event into its scripted parts.
pub fn decode_event(
    event: &RawEvent<'_>,
) -> Result<(EvidencePhase, OperationClass, CallKind, i32), BackendError> {
    if event.header.backend_id != BACKEND_SYNTHETIC {
        return Err(corrupt("backend_id"));
    }
    if event.header.event_kind != EVENT_OBSERVATION {
        return Err(crate::synthetic::unsupported_kind("event_kind"));
    }
    if event.payload.len() != 8 {
        return Err(corrupt("payload_len"));
    }
    if event.payload[0] != CODEC_VERSION {
        return Err(corrupt("codec_version"));
    }
    let phase = phase_at(event.payload[1]).ok_or_else(|| corrupt("phase"))?;
    let class = class_at(event.payload[2]).ok_or_else(|| corrupt("class"))?;
    let call = call_at(event.payload[3]).ok_or_else(|| corrupt("call"))?;
    let mut code = [0_u8; 4];
    code.copy_from_slice(&event.payload[4..8]);
    Ok((phase, class, call, i32::from_le_bytes(code)))
}

/// Validation failure naming the offending field.
fn corrupt(field: &'static str) -> BackendError {
    BackendError::CorruptInput(InputReason::new(field))
}

/// Phase wire order, including the internal `Succeeded` slot.
const fn phase_index(phase: EvidencePhase) -> u8 {
    match phase {
        EvidencePhase::Discovered => 0,
        EvidencePhase::Selected => 1,
        EvidencePhase::Entered => 2,
        EvidencePhase::Returned => 3,
        EvidencePhase::Completed => 4,
        EvidencePhase::Succeeded => 5,
    }
}

/// Inverse of [`phase_index`]; `None` outside the table.
const fn phase_at(index: u8) -> Option<EvidencePhase> {
    match index {
        0 => Some(EvidencePhase::Discovered),
        1 => Some(EvidencePhase::Selected),
        2 => Some(EvidencePhase::Entered),
        3 => Some(EvidencePhase::Returned),
        4 => Some(EvidencePhase::Completed),
        5 => Some(EvidencePhase::Succeeded),
        _ => None,
    }
}

/// Class table order follows `OperationClass` declaration order.
const fn class_index(class: OperationClass) -> u8 {
    match class {
        OperationClass::Sign => 0,
        OperationClass::Verify => 1,
        OperationClass::Encrypt => 2,
        OperationClass::Decrypt => 3,
        OperationClass::Digest => 4,
        OperationClass::Mac => 5,
        OperationClass::Kdf => 6,
        OperationClass::KeyAgreement => 7,
        OperationClass::KemEncapsulate => 8,
        OperationClass::KemDecapsulate => 9,
        OperationClass::Random => 10,
        OperationClass::KeyManagement => 11,
        OperationClass::Unknown => 12,
    }
}

/// Inverse of [`class_index`]; `None` outside the table.
const fn class_at(index: u8) -> Option<OperationClass> {
    match index {
        0 => Some(OperationClass::Sign),
        1 => Some(OperationClass::Verify),
        2 => Some(OperationClass::Encrypt),
        3 => Some(OperationClass::Decrypt),
        4 => Some(OperationClass::Digest),
        5 => Some(OperationClass::Mac),
        6 => Some(OperationClass::Kdf),
        7 => Some(OperationClass::KeyAgreement),
        8 => Some(OperationClass::KemEncapsulate),
        9 => Some(OperationClass::KemDecapsulate),
        10 => Some(OperationClass::Random),
        11 => Some(OperationClass::KeyManagement),
        12 => Some(OperationClass::Unknown),
        _ => None,
    }
}

/// Call-kind table order follows `CallKind` declaration order.
const fn call_index(call: CallKind) -> u8 {
    match call {
        CallKind::Operation => 0,
        CallKind::Initialization => 1,
        CallKind::SizeQuery => 2,
        CallKind::Update => 3,
        CallKind::Finalization => 4,
        CallKind::Unknown => 5,
    }
}

/// Inverse of [`call_index`]; `None` outside the table.
const fn call_at(index: u8) -> Option<CallKind> {
    match index {
        0 => Some(CallKind::Operation),
        1 => Some(CallKind::Initialization),
        2 => Some(CallKind::SizeQuery),
        3 => Some(CallKind::Update),
        4 => Some(CallKind::Finalization),
        5 => Some(CallKind::Unknown),
        _ => None,
    }
}
