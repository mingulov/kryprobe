// SPDX-License-Identifier: GPL-3.0-or-later
//! Session machine tests: legal path + full 9x9 transition table.

use kryprobe_core::session::{SessionController, SessionError, SessionState};

/// All nine states: 8 ARCH §4.1 states + FAILED_PARTIAL.
const ALL: [SessionState; 9] = [
    SessionState::Created,
    SessionState::Qualified,
    SessionState::Discovering,
    SessionState::Attaching,
    SessionState::Observing,
    SessionState::Quiescing,
    SessionState::Draining,
    SessionState::Finalized,
    SessionState::FailedPartial,
];

/// The 15 legal edges: 7-chain + 7 fail-outs + failed->finalized.
fn is_legal(from: SessionState, to: SessionState) -> bool {
    use SessionState as S;
    matches!(
        (from, to),
        (S::Created, S::Qualified)
            | (S::Qualified, S::Discovering)
            | (S::Discovering, S::Attaching)
            | (S::Attaching, S::Observing)
            | (S::Observing, S::Quiescing)
            | (S::Quiescing, S::Draining)
            | (S::Draining, S::Finalized)
            | (S::FailedPartial, S::Finalized)
            | (
                S::Created
                    | S::Qualified
                    | S::Discovering
                    | S::Attaching
                    | S::Observing
                    | S::Quiescing
                    | S::Draining,
                S::FailedPartial
            )
    )
}

/// Drive a fresh controller from CREATED to any reachable state.
fn at(state: SessionState) -> SessionController {
    let mut ctrl = SessionController::new();
    if state == SessionState::Created {
        return ctrl;
    }
    if state == SessionState::FailedPartial {
        ctrl.transition(SessionState::FailedPartial)
            .expect("created->failed_partial is legal");
        return ctrl;
    }
    let chain = [
        SessionState::Qualified,
        SessionState::Discovering,
        SessionState::Attaching,
        SessionState::Observing,
        SessionState::Quiescing,
        SessionState::Draining,
        SessionState::Finalized,
    ];
    for next in chain {
        ctrl.transition(next).expect("chain step must be legal");
        if next == state {
            return ctrl;
        }
    }
    panic!("unreachable test state: {state:?}");
}

#[test]
fn legal_path_reaches_finalized() {
    let mut ctrl = at(SessionState::Draining);
    assert_eq!(ctrl.state(), SessionState::Draining);
    assert!(ctrl.transition(SessionState::Finalized).is_ok());
    assert_eq!(ctrl.state(), SessionState::Finalized);
}

#[test]
fn failed_partial_recovers_to_finalized() {
    let mut ctrl = at(SessionState::Observing);
    assert!(ctrl.transition(SessionState::FailedPartial).is_ok());
    assert_eq!(ctrl.state(), SessionState::FailedPartial);
    assert!(ctrl.transition(SessionState::Finalized).is_ok());
    assert_eq!(ctrl.state(), SessionState::Finalized);
}

#[test]
fn full_transition_table_all_pairs_asserted() {
    let mut legal_count = 0;
    for from in ALL {
        for to in ALL {
            let mut ctrl = at(from);
            let result = ctrl.transition(to);
            if is_legal(from, to) {
                legal_count += 1;
                assert!(result.is_ok(), "({from:?} -> {to:?}) must be legal");
                assert_eq!(ctrl.state(), to);
            } else {
                assert_eq!(
                    result,
                    Err(SessionError::IllegalTransition { from, to }),
                    "({from:?} -> {to:?}) must be illegal"
                );
                assert_eq!(ctrl.state(), from, "failed hop must not move");
            }
        }
    }
    assert_eq!(legal_count, 15, "exactly 15 legal edges expected");
}
