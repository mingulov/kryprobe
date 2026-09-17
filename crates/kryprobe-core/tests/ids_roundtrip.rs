// SPDX-License-Identifier: GPL-3.0-or-later
//! ID string round-trips: every ID parses its `kind:value` display form,
//! serializes to the same string, and rejects bad shapes.

use kryprobe_core::ids::{
    CorrelationId, IdParseError, ImplementationId, ObjectId, ObservationId, PlanGeneration,
    ProcessGeneration, SessionId, TargetId,
};
use std::str::FromStr;

#[test]
fn ids_display_and_parse_roundtrip() {
    assert_eq!(SessionId::new(1).to_string(), "session:1");
    assert_eq!(TargetId::new(2).to_string(), "target:2");
    assert_eq!(ObjectId::new(3).to_string(), "object:3");
    assert_eq!(ImplementationId::new(4).to_string(), "implementation:4");
    assert_eq!(ObservationId::new(5).to_string(), "observation:5");
    assert_eq!(CorrelationId::new(6).to_string(), "correlation:6");
    assert_eq!(PlanGeneration::new(7).to_string(), "plan_generation:7");
    assert_eq!(
        ProcessGeneration::new(8).to_string(),
        "process_generation:8"
    );

    assert_eq!(SessionId::from_str("session:1"), Ok(SessionId::new(1)));
    assert_eq!(TargetId::from_str("target:2"), Ok(TargetId::new(2)));
    assert_eq!(ObjectId::from_str("object:3"), Ok(ObjectId::new(3)));
    assert_eq!(
        ImplementationId::from_str("implementation:4"),
        Ok(ImplementationId::new(4))
    );
    assert_eq!(
        ObservationId::from_str("observation:5"),
        Ok(ObservationId::new(5))
    );
    assert_eq!(
        CorrelationId::from_str("correlation:6"),
        Ok(CorrelationId::new(6))
    );
    assert_eq!(
        PlanGeneration::from_str("plan_generation:7"),
        Ok(PlanGeneration::new(7))
    );
    assert_eq!(
        ProcessGeneration::from_str("process_generation:8"),
        Ok(ProcessGeneration::new(8))
    );
}

#[test]
fn ids_serde_json_string_roundtrip() {
    let session = SessionId::new(340_282_366_920_938_463_463_374_607_431_768_211_455);
    let text = serde_json::to_string(&session).unwrap();
    assert_eq!(text, format!("\"{session}\""));
    assert_eq!(serde_json::from_str::<SessionId>(&text).unwrap(), session);

    let target = TargetId::new(u64::MAX);
    let text = serde_json::to_string(&target).unwrap();
    assert_eq!(text, "\"target:18446744073709551615\"");
    assert_eq!(serde_json::from_str::<TargetId>(&text).unwrap(), target);
}

#[test]
fn ids_reject_bad_shapes() {
    assert!(SessionId::from_str("session:").is_err());
    assert!(SessionId::from_str("session").is_err());
    assert!(SessionId::from_str("target:1").is_err());
    assert!(SessionId::from_str("Session:1").is_err());
    assert!(SessionId::from_str("session:12a").is_err());
    assert!(SessionId::from_str("session:+12").is_err());
    assert!(SessionId::from_str("session:-1").is_err());
    assert!(SessionId::from_str("session: 1").is_err());
    assert!(TargetId::from_str("target:18446744073709551616").is_err());
    assert!(PlanGeneration::from_str("plan_generation:4294967296").is_err());
    assert!(ProcessGeneration::from_str("process_generation:xyz").is_err());
    assert!(serde_json::from_str::<ObjectId>("\"nope\"").is_err());
    assert!(serde_json::from_str::<ObservationId>("42").is_err());

    let err = CorrelationId::from_str("bogus").unwrap_err();
    assert_eq!(
        err,
        IdParseError::new("correlation", "bogus"),
        "error names the expected kind"
    );
}
