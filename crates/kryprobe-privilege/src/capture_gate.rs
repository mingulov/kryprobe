//! Lane-test capture gate: shared-VM stray-traffic retry verdicts.
//!
//! Kernel-wide BPF aggregates see every process's crypto traffic, so a
//! background op during a lane test's capture window merges into the
//! asserted cells (observed once on a hosted runner: an E2E cell read
//! `(9, 26232, 9, 0, 0)` against a `(8, 512, 8, 0, 0)` truth — a
//! foreign 25720-byte op no 64-byte fixture input can produce).
//!
//! Test-support API: each exact-count lane test mirrors its asserted
//! cells as a [`GateCell`] table and checks the capture BEFORE
//! asserting. [`CaptureVerdict::Excess`] re-captures on a fresh
//! sensor (bounded); [`CaptureVerdict::Short`] fails immediately (a
//! sensor miss, never contamination); repeated excess fails closed.
//! Exactness is preserved: only a [`CaptureVerdict::Clean`] capture
//! reaches the truth assertions.

/// `(calls, bytes, ok, errors, queued)` sums for one asserted cell.
pub type CellSums = (u64, u64, u64, u64, u64);

/// Expected byte shape of a gated cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BytesShape {
    /// `bytes == per_call * calls`.
    PerCall(u64),
    /// Unconstrained (e.g. alloc rows carry no meaningful bytes).
    Any,
}

/// Expected class shape of a gated cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassShape {
    /// Exact `(ok, errors, queued)`.
    Exact(u64, u64, u64),
    /// `(ok, errors, queued) == (calls, 0, 0)` at the observed
    /// in-range call count (bounded skcipher cells, G9).
    CallsOk,
    /// Unconstrained (the test only gates calls).
    Any,
}

/// One gated cell: an asserted `(family, op, result, alg)` counter
/// with its fixture-truth bounds. Bounds must mirror the test's
/// truth assertions exactly — the gate never accepts a capture the
/// assertions would reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateCell {
    /// Stable label for retry/failure messages (`family/op`).
    pub label: &'static str,
    /// `KFAM_*` selector.
    pub fam: u8,
    /// `KOP_*` selector.
    pub op: u8,
    /// `KRES_*` selector.
    pub res: u8,
    /// Requested algorithm name.
    pub alg: &'static str,
    /// Minimum accepted calls (below = sensor miss).
    pub min_calls: u64,
    /// Maximum accepted calls (above = contamination).
    pub max_calls: u64,
    /// Byte-shape rule.
    pub bytes: BytesShape,
    /// Class-shape rule.
    pub class: ClassShape,
}

impl GateCell {
    /// Exact cell: `calls` calls of `per_call` bytes with an exact
    /// `(ok, errors, queued)` class tuple.
    #[allow(clippy::too_many_arguments)]
    pub const fn exact(
        label: &'static str,
        fam: u8,
        op: u8,
        res: u8,
        alg: &'static str,
        calls: u64,
        per_call: u64,
        ok: u64,
        errors: u64,
        queued: u64,
    ) -> Self {
        Self {
            label,
            fam,
            op,
            res,
            alg,
            min_calls: calls,
            max_calls: calls,
            bytes: BytesShape::PerCall(per_call),
            class: ClassShape::Exact(ok, errors, queued),
        }
    }

    /// Bounded cell with exact shape at the observed count
    /// (`bytes == per_call * calls`, `ok == calls`, no err/queued).
    #[allow(clippy::too_many_arguments)]
    pub const fn bounded(
        label: &'static str,
        fam: u8,
        op: u8,
        res: u8,
        alg: &'static str,
        min_calls: u64,
        max_calls: u64,
        per_call: u64,
    ) -> Self {
        Self {
            label,
            fam,
            op,
            res,
            alg,
            min_calls,
            max_calls,
            bytes: BytesShape::PerCall(per_call),
            class: ClassShape::CallsOk,
        }
    }

    /// Calls-plus-bytes cell: a calls range with `PerCall` bytes and
    /// unconstrained class (the test asserts calls + bytes but leaves
    /// the ok value product-unspecified, e.g. alloc rows).
    #[allow(clippy::too_many_arguments)]
    pub const fn calls_bytes(
        label: &'static str,
        fam: u8,
        op: u8,
        res: u8,
        alg: &'static str,
        min_calls: u64,
        max_calls: u64,
        per_call: u64,
    ) -> Self {
        Self {
            label,
            fam,
            op,
            res,
            alg,
            min_calls,
            max_calls,
            bytes: BytesShape::PerCall(per_call),
            class: ClassShape::Any,
        }
    }

    /// Calls-only cell (byte/class shape unconstrained).
    pub const fn calls(
        label: &'static str,
        fam: u8,
        op: u8,
        res: u8,
        alg: &'static str,
        min_calls: u64,
        max_calls: u64,
    ) -> Self {
        Self {
            label,
            fam,
            op,
            res,
            alg,
            min_calls,
            max_calls,
            bytes: BytesShape::Any,
            class: ClassShape::Any,
        }
    }
}

/// Capture-gate verdict.
#[derive(Debug, PartialEq, Eq)]
pub enum CaptureVerdict {
    /// Every asserted cell matches: proceed to the truth assertions.
    Clean,
    /// A cell EXCEEDS the fixture truth (calls above max, or shape
    /// skew at/above expected calls): contamination-shaped —
    /// re-capture on a fresh sensor.
    Excess(String),
    /// A cell is BELOW the fixture truth: a sensor miss, never
    /// contamination — fail immediately, no retry.
    Short(String),
}

/// Check every cell's sums against its bounds. `sums` maps each cell
/// to its observed `(calls, bytes, ok, errors, queued)`; shortfall
/// reports before excess within a cell, cells evaluate in order.
pub fn check_cells<F>(cells: &[GateCell], sums: F) -> CaptureVerdict
where
    F: Fn(&GateCell) -> CellSums,
{
    for cell in cells {
        let got = sums(cell);
        if got.0 < cell.min_calls {
            return CaptureVerdict::Short(format!(
                "{}: calls {} < min {} ({got:?})",
                cell.label, got.0, cell.min_calls
            ));
        }
        if got.0 > cell.max_calls {
            return CaptureVerdict::Excess(format!(
                "{}: calls {} > max {} ({got:?})",
                cell.label, got.0, cell.max_calls
            ));
        }
        // In-range calls with skewed shape: contamination-shaped
        // (stray bytes merge into our rows). A systematic product
        // skew fails closed after the bounded attempts with the
        // offending tuple attached.
        if let BytesShape::PerCall(per_call) = cell.bytes
            && got.1 != got.0 * per_call
        {
            return CaptureVerdict::Excess(format!(
                "{}: bytes {} != {per_call}×calls {} ({got:?})",
                cell.label, got.1, got.0
            ));
        }
        match cell.class {
            ClassShape::Exact(ok, errors, queued)
                if (got.2, got.3, got.4) != (ok, errors, queued) =>
            {
                return CaptureVerdict::Excess(format!(
                    "{}: class ({}, {}, {}) != ({ok}, {errors}, {queued}) ({got:?})",
                    cell.label, got.2, got.3, got.4
                ));
            }
            ClassShape::CallsOk if (got.2, got.3, got.4) != (got.0, 0, 0) => {
                return CaptureVerdict::Excess(format!(
                    "{}: class shape skew ({got:?})",
                    cell.label
                ));
            }
            _ => {}
        }
    }
    CaptureVerdict::Clean
}

#[cfg(test)]
mod tests {
    use super::*;

    const CELL: GateCell = GateCell::exact("t/op", 1, 2, 3, "t-alg", 8, 64, 8, 0, 0);

    #[test]
    fn exact_truth_is_clean() {
        assert_eq!(
            check_cells(&[CELL], |_| (8, 512, 8, 0, 0)),
            CaptureVerdict::Clean
        );
    }

    #[test]
    fn excess_calls_is_excess() {
        assert!(matches!(
            check_cells(&[CELL], |_| (9, 26232, 9, 0, 0)),
            CaptureVerdict::Excess(_)
        ));
    }

    #[test]
    fn short_calls_is_short() {
        assert!(matches!(
            check_cells(&[CELL], |_| (7, 448, 7, 0, 0)),
            CaptureVerdict::Short(_)
        ));
    }

    #[test]
    fn bytes_skew_at_exact_calls_is_excess() {
        assert!(matches!(
            check_cells(&[CELL], |_| (8, 600, 8, 0, 0)),
            CaptureVerdict::Excess(_)
        ));
    }

    #[test]
    fn class_skew_is_excess() {
        assert!(matches!(
            check_cells(&[CELL], |_| (8, 512, 7, 1, 0)),
            CaptureVerdict::Excess(_)
        ));
    }

    #[test]
    fn bounded_calls_ok_edges() {
        const BOUNDED: GateCell = GateCell::bounded("t/op", 1, 2, 3, "t-alg", 18, 20, 32);
        assert_eq!(
            check_cells(&[BOUNDED], |_| (18, 576, 18, 0, 0)),
            CaptureVerdict::Clean
        );
        assert_eq!(
            check_cells(&[BOUNDED], |_| (20, 640, 20, 0, 0)),
            CaptureVerdict::Clean
        );
        assert!(matches!(
            check_cells(&[BOUNDED], |_| (17, 544, 17, 0, 0)),
            CaptureVerdict::Short(_)
        ));
        assert!(matches!(
            check_cells(&[BOUNDED], |_| (21, 672, 21, 0, 0)),
            CaptureVerdict::Excess(_)
        ));
        // In-range calls with non-ok class: excess, not clean.
        assert!(matches!(
            check_cells(&[BOUNDED], |_| (19, 608, 18, 1, 0)),
            CaptureVerdict::Excess(_)
        ));
    }

    #[test]
    fn calls_bytes_gates_calls_and_bytes_only() {
        const CELL: GateCell = GateCell::calls_bytes("t/op", 1, 2, 3, "t-alg", 1, 1, 0);
        // Class is ignored even when nonzero.
        assert_eq!(
            check_cells(&[CELL], |_| (1, 0, 0, 0, 0)),
            CaptureVerdict::Clean
        );
        assert_eq!(
            check_cells(&[CELL], |_| (1, 0, 7, 0, 0)),
            CaptureVerdict::Clean
        );
        assert!(matches!(
            check_cells(&[CELL], |_| (1, 8, 1, 0, 0)),
            CaptureVerdict::Excess(_)
        ));
        assert!(matches!(
            check_cells(&[CELL], |_| (2, 0, 2, 0, 0)),
            CaptureVerdict::Excess(_)
        ));
    }

    #[test]
    fn calls_only_ignores_shape() {
        const CALLS: GateCell = GateCell::calls("t/op", 1, 2, 3, "t-alg", 1, 1);
        assert_eq!(
            check_cells(&[CALLS], |_| (1, 999, 0, 0, 0)),
            CaptureVerdict::Clean
        );
        assert!(matches!(
            check_cells(&[CALLS], |_| (2, 0, 2, 0, 0)),
            CaptureVerdict::Excess(_)
        ));
        assert!(matches!(
            check_cells(&[CALLS], |_| (0, 0, 0, 0, 0)),
            CaptureVerdict::Short(_)
        ));
    }

    #[test]
    fn first_offending_cell_reports() {
        const OTHER: GateCell = GateCell::exact("o/op", 4, 5, 6, "o-alg", 1, 0, 1, 0, 0);
        let verdict = check_cells(&[CELL, OTHER], |c| {
            if c.label == "t/op" {
                (8, 512, 8, 0, 0)
            } else {
                (2, 0, 2, 0, 0)
            }
        });
        assert!(matches!(verdict, CaptureVerdict::Excess(d) if d.starts_with("o/op")));
    }
}
