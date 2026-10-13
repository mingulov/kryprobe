// SPDX-License-Identifier: GPL-3.0-or-later
//! Aggregate program-miss telemetry (M1 Stage 1): per-program
//! `recursion_misses`/`run_cnt` absolutes read through retained
//! program FDs, joined across the capture by (`section`,
//! `program_id`) bijection.
//!
//! The lifecycle reader (`kcrypto_lifecycle::view`) is the syscall
//! starting point (shared [`crate::probe::bpf_sys::obj_get_info`]
//! helper, same pinned 7.0 UAPI offsets), but its join is NOT reused:
//! it matches by section only, ignores program IDs, and accepts
//! duplicates. This join requires an exact bijection on
//! (`section`, `program_id`) — replacement, duplicate, vanished,
//! appeared, reset, and saturated inputs all refuse loudly, never
//! read as zero loss.
//!
//! Section labels come from the actually loaded object bytes (parsed
//! once at configure time into a name→section table): the aggregate
//! loader retains program *names*, and re-deriving sections from any
//! other source would duplicate loader knowledge or hardcode the
//! mapping. A retained name missing from the table refuses as
//! [`MissError::Unlabeled`].
//!
//! `run_cnt` rides along as the accepted-program cross-check with
//! stats-gated interpretation: it is evidence only when runtime
//! statistics were enabled at BOTH endpoints (recorded per snapshot
//! from the world-readable sysctl — the product never enables
//! statistics itself). Misses need no enabling (verified on 7.0.14:
//! I-NC64 leg0, M > 0 with stats off).

use crate::bpfloader::parse_kcrypto_object;
use crate::fd::OwnedFd;
use crate::probe::bpf_sys::{BPF_PROG_TYPE_TRACING, obj_get_info};
use std::collections::{HashMap, HashSet};

// Pinned 7.0 `bpf_prog_info` UAPI layout (independently verified by
// `offsetof` probe against linux/bpf.h; duplicated — not imported —
// from the lifecycle view so this module pins its own contract):
// type@0 u32, id@4 u32, run_time_ns@192 u64, run_cnt@200 u64,
// recursion_misses@208 u64.
const PROG_ID_OFF: usize = 4;
const RUN_CNT_OFF: usize = 200;
const RECURSION_MISSES_OFF: usize = 208;
const PROG_MISS_PREFIX: u32 = 216;
const INFO_BUF: usize = 512;

/// One program's miss absolutes at one endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggProgMissAbs {
    /// ELF section (`fexit/<symbol>`) from the loaded object bytes.
    pub section: String,
    /// Kernel program ID read from the retained FD.
    pub program_id: u32,
    /// `recursion_misses` absolute (guard skips).
    pub misses: u64,
    /// `run_cnt` absolute (accepted executions; counted only while
    /// runtime statistics are enabled).
    pub run_cnt: u64,
    /// `kernel.bpf_stats_enabled` at read time (`None` = unreadable).
    pub stats_enabled: Option<bool>,
}

/// One program's joined miss delta across the capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggProgMissDelta {
    /// ELF section (join key, stable).
    pub section: String,
    /// Kernel program ID (join key; equality proves no replacement).
    pub program_id: u32,
    /// Baseline `recursion_misses` absolute.
    pub miss_baseline: u64,
    /// Current `recursion_misses` absolute.
    pub miss_current: u64,
    /// Guard skips during the capture (current − baseline).
    pub miss_delta: u64,
    /// Accepted executions during the capture — `Some` only when
    /// statistics were enabled at BOTH endpoints (else the counter
    /// did not count and no evidence exists). Never zero-filled.
    pub run_delta: Option<u64>,
}

/// Miss telemetry failure: every variant refuses (loud), never a
/// silent zero. Read-stage and join-stage share the type; the stage
/// is evident from the variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MissError {
    /// `BPF_OBJ_GET_INFO_BY_FD` refused (errno preserved).
    GetInfo {
        /// Which program (`prog <section-or-name>`).
        stage: String,
        /// Raw errno.
        errno: i32,
    },
    /// Short info report (ancient kernel — never read past it).
    InfoShort {
        /// Which program.
        stage: String,
        /// Bytes the kernel reported.
        got: u32,
        /// Bytes required (216).
        want: u32,
    },
    /// Program is not a tracing (fexit) program.
    WrongType {
        /// Which program.
        stage: String,
        /// Reported `bpf_prog_info.type`.
        got: u32,
    },
    /// Retained program name has no section in the loaded object.
    Unlabeled {
        /// The retained name.
        name: String,
    },
    /// Section appears twice on one side (ambiguous join).
    DuplicateSection {
        /// The section.
        section: String,
    },
    /// Program ID appears twice on one side (corrupt input).
    DuplicateId {
        /// The program ID.
        id: u32,
    },
    /// Same section, different program ID (program replaced
    /// mid-session — delta unknown, never zero).
    Replacement {
        /// The section.
        section: String,
        /// Baseline program ID.
        from: u32,
        /// Current program ID.
        to: u32,
    },
    /// Current pair with no baseline (program appeared mid-session).
    Appeared {
        /// The section.
        section: String,
        /// The program ID.
        id: u32,
    },
    /// Baseline pair gone from current (program vanished mid-session).
    Vanished {
        /// The section.
        section: String,
        /// The program ID.
        id: u32,
    },
    /// A counter ran backwards (misses or run_cnt) — never zero loss.
    Reset {
        /// The section.
        section: String,
    },
    /// A counter absolute is saturated (`MAX`) — already-saturated
    /// inputs refuse (ADR-0008 §(e)), same as the checked folds.
    Saturated {
        /// The section.
        section: String,
    },
    /// Empty baseline (never armed) — an unbaselined join refuses.
    Unarmed,
}

impl std::fmt::Display for MissError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MissError::GetInfo { stage, errno } => {
                write!(f, "{stage}: GET_INFO refused (errno {errno})")
            }
            MissError::InfoShort { stage, got, want } => {
                write!(f, "{stage}: short info ({got} < {want})")
            }
            MissError::WrongType { stage, got } => {
                write!(f, "{stage}: prog type {got} is not TRACING")
            }
            MissError::Unlabeled { name } => {
                write!(f, "prog {name}: no section in loaded object")
            }
            MissError::DuplicateSection { section } => {
                write!(f, "prog_misses[{section}]: duplicate section")
            }
            MissError::DuplicateId { id } => {
                write!(f, "prog_misses[id {id}]: duplicate program id")
            }
            MissError::Replacement { section, from, to } => {
                write!(
                    f,
                    "prog_misses[{section}]: program replaced (id {from} -> {to}); delta unknown"
                )
            }
            MissError::Appeared { section, id } => {
                write!(f, "prog_misses[{section}#{id}]: no baseline")
            }
            MissError::Vanished { section, id } => {
                write!(f, "prog_misses[{section}#{id}]: baseline has no current")
            }
            MissError::Reset { section } => {
                write!(f, "prog_misses[{section}]: counter ran backwards")
            }
            MissError::Saturated { section } => {
                write!(f, "prog_misses[{section}]: counter saturated")
            }
            MissError::Unarmed => write!(f, "prog_misses: empty baseline"),
        }
    }
}

impl std::error::Error for MissError {}

/// Terminal miss account: joined deltas, or a typed unavailable
/// (fail-soft — an unreadable miss counter keeps the capture
/// partial-capable, never fails it and never reads as zero).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MissTerminal {
    /// Joined per-program deltas (one per program, both endpoints).
    Available(Vec<AggProgMissDelta>),
    /// Telemetry unavailable (reason preserved for the verdict path).
    Unavailable {
        /// Why (miss read/join refusal detail).
        reason: String,
    },
}

/// Build the retained-name → ELF-section table from the actually
/// loaded object bytes (parsed once at configure time). A duplicate
/// name refuses the whole table (`None` — the join would be
/// ambiguous); object-parse failure likewise yields `None` (the
/// caller treats it as unavailable telemetry, never a load failure).
pub fn miss_sections_for_object(bytes: &[u8]) -> Option<HashMap<String, String>> {
    let parsed = parse_kcrypto_object(bytes).ok()?;
    let mut table = HashMap::with_capacity(parsed.programs.len());
    for prog in &parsed.programs {
        if table.contains_key(&prog.name) {
            return None;
        }
        table.insert(prog.name.clone(), prog.section.clone());
    }
    Some(table)
}

fn u32le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap_or([0; 4]))
}

fn u64le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap_or([0; 8]))
}

/// Read `kernel.bpf_stats_enabled` (world-readable; `None` when
/// unreadable or unparseable — never a defaulted assumption).
fn read_stats_enabled() -> Option<bool> {
    let text = std::fs::read_to_string("/proc/sys/kernel/bpf_stats_enabled").ok()?;
    match text.trim() {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

/// Snapshot every retained program's miss absolutes (M1 aggregate
/// telemetry): same `BPF_OBJ_GET_INFO_BY_FD` path as the lifecycle
/// reader (shared helper, same TRACING pin, same 216-byte prefix —
/// a short report refuses, never reads past it). Sections resolve
/// through the configure-time table; an unresolvable name refuses
/// (never a guessed label).
pub fn snapshot_agg_misses(
    progs: &[(String, OwnedFd)],
    sections: &HashMap<String, String>,
) -> Result<Vec<AggProgMissAbs>, MissError> {
    let stats_enabled = read_stats_enabled();
    let mut out = Vec::with_capacity(progs.len());
    for (name, fd) in progs {
        let section = sections
            .get(name)
            .ok_or_else(|| MissError::Unlabeled { name: name.clone() })?;
        let stage = format!("prog {section}");
        let mut buf = [0u8; INFO_BUF];
        let got = obj_get_info(fd.as_raw_fd(), &mut buf).map_err(|errno| MissError::GetInfo {
            stage: stage.clone(),
            errno,
        })?;
        if got < PROG_MISS_PREFIX {
            return Err(MissError::InfoShort {
                stage,
                got,
                want: PROG_MISS_PREFIX,
            });
        }
        if u32le(&buf, 0) != BPF_PROG_TYPE_TRACING {
            return Err(MissError::WrongType {
                stage,
                got: u32le(&buf, 0),
            });
        }
        out.push(AggProgMissAbs {
            section: section.clone(),
            program_id: u32le(&buf, PROG_ID_OFF),
            misses: u64le(&buf, RECURSION_MISSES_OFF),
            run_cnt: u64le(&buf, RUN_CNT_OFF),
            stats_enabled,
        });
    }
    Ok(out)
}

/// Join baseline and current miss absolutes by (`section`,
/// `program_id`) bijection (pure — unit-tested without privilege).
/// Both sides must carry each pair exactly once with monotone,
/// unsaturated counters; anything else refuses (replacement,
/// duplicate, vanished, appeared, reset, saturated, unarmed).
/// `run_delta` is `Some` only when statistics were enabled at BOTH
/// endpoints — toggled or disabled statistics yield `None` (no
/// evidence), while the miss delta still joins (misses need no
/// enabling).
pub fn join_agg_miss_deltas(
    baseline: &[AggProgMissAbs],
    current: &[AggProgMissAbs],
) -> Result<Vec<AggProgMissDelta>, MissError> {
    if baseline.is_empty() {
        return Err(MissError::Unarmed);
    }
    for side in [baseline, current] {
        let mut sections = HashSet::with_capacity(side.len());
        let mut ids = HashSet::with_capacity(side.len());
        for abs in side {
            if !sections.insert(abs.section.clone()) {
                return Err(MissError::DuplicateSection {
                    section: abs.section.clone(),
                });
            }
            if !ids.insert(abs.program_id) {
                return Err(MissError::DuplicateId { id: abs.program_id });
            }
        }
    }
    let mut out = Vec::with_capacity(current.len());
    for got in current {
        let same_section: Vec<&AggProgMissAbs> = baseline
            .iter()
            .filter(|w| w.section == got.section)
            .collect();
        match same_section.as_slice() {
            [] => {
                return Err(MissError::Appeared {
                    section: got.section.clone(),
                    id: got.program_id,
                });
            }
            [want] => {
                if want.program_id != got.program_id {
                    return Err(MissError::Replacement {
                        section: got.section.clone(),
                        from: want.program_id,
                        to: got.program_id,
                    });
                }
                if got.misses < want.misses || got.run_cnt < want.run_cnt {
                    return Err(MissError::Reset {
                        section: got.section.clone(),
                    });
                }
                if want.misses == u64::MAX
                    || got.misses == u64::MAX
                    || want.run_cnt == u64::MAX
                    || got.run_cnt == u64::MAX
                {
                    return Err(MissError::Saturated {
                        section: got.section.clone(),
                    });
                }
                let run_delta = match (want.stats_enabled, got.stats_enabled) {
                    (Some(true), Some(true)) => Some(got.run_cnt - want.run_cnt),
                    _ => None,
                };
                out.push(AggProgMissDelta {
                    section: got.section.clone(),
                    program_id: got.program_id,
                    miss_baseline: want.misses,
                    miss_current: got.misses,
                    miss_delta: got.misses - want.misses,
                    run_delta,
                });
            }
            _ => {
                // Unreachable (duplicates refused above), kept loud.
                return Err(MissError::DuplicateSection {
                    section: got.section.clone(),
                });
            }
        }
    }
    for want in baseline {
        if !current.iter().any(|g| g.section == want.section) {
            return Err(MissError::Vanished {
                section: want.section.clone(),
                id: want.program_id,
            });
        }
    }
    Ok(out)
}

/// Map a miss join verdict to the terminal account (the ONE
/// join→terminal mapping: [`crate::kcrypto_backend::KCryptoBackend::session_miss_terminal`]
/// and the F03 interval oracles share it, so tests assert the
/// production meaning — never a re-derived copy).
pub fn miss_terminal_from_join(joined: Result<Vec<AggProgMissDelta>, MissError>) -> MissTerminal {
    match joined {
        Ok(deltas) => MissTerminal::Available(deltas),
        Err(err) => MissTerminal::Unavailable {
            reason: format!("miss join refused: {err}"),
        },
    }
}

/// Terminal account when the bring-up baseline read failed (the
/// fail-soft arm shared by
/// [`crate::kcrypto_backend::KCryptoBackend::session_miss_terminal`]
/// and the F03 interval oracles — an unreadable baseline is explicit
/// unavailability, never measured zero).
pub fn miss_terminal_no_baseline() -> MissTerminal {
    MissTerminal::Unavailable {
        reason: "miss baseline unavailable (pre-attach read failed)".to_owned(),
    }
}

/// Bring-up sequencing: load → baseline-read → attach (F03/BPF1).
///
/// The miss baseline reads the loaded-but-unattached `staged` state
/// by shared borrow; `attach` then consumes it into the live sensor.
/// The borrow-then-move boundary makes baseline-after-attach
/// unrepresentable: no execution can precede the baseline because no
/// link exists yet, so bring-up misses share the admitted capture's
/// start — counted or unavailable, never subtracted into a measured
/// zero (`bringup_misses_share_admission_interval` pins this; the
/// pre-F03 attach-then-baseline order fails it).
///
/// Generic over the staged (`S`) and attached (`T`) states so the
/// production loader path and the scripted oracles run the same
/// sequence: production passes the staged loader halves, tests pass
/// scripted stages with injected bring-up-window activity.
pub fn run_bringup_with_baseline<S, T, E>(
    staged: S,
    read_baseline: impl FnOnce(&S) -> Option<Vec<AggProgMissAbs>>,
    attach: impl FnOnce(S) -> Result<T, E>,
) -> Result<(T, Option<Vec<AggProgMissAbs>>), E> {
    let baseline = read_baseline(&staged);
    let sensor = attach(staged)?;
    Ok((sensor, baseline))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abs(section: &str, id: u32, misses: u64, run: u64, stats: Option<bool>) -> AggProgMissAbs {
        AggProgMissAbs {
            section: section.to_owned(),
            program_id: id,
            misses,
            run_cnt: run,
            stats_enabled: stats,
        }
    }

    #[test]
    fn miss_snapshot_program_replacement_is_unknown() {
        // Same section, different program ID (program replaced
        // mid-session): the delta is UNKNOWN — refuse, never join
        // across the replacement and never read zero.
        let baseline = vec![abs("fexit/f", 11, 3, 100, Some(true))];
        let current = vec![abs("fexit/f", 12, 9, 200, Some(true))];
        let err = join_agg_miss_deltas(&baseline, &current).expect_err("replacement refuses");
        assert!(matches!(err, MissError::Replacement { .. }), "{err:?}");
    }

    #[test]
    fn duplicate_program_section_is_refused() {
        // A section twice on one side is ambiguous even with distinct
        // IDs (and distinct sections sharing one ID are corrupt) —
        // both refuse. Shuffled input order still joins.
        let baseline = vec![
            abs("fexit/a", 11, 3, 100, Some(true)),
            abs("fexit/b", 12, 0, 50, Some(true)),
        ];
        let dup_section = vec![
            abs("fexit/b", 12, 2, 60, Some(true)),
            abs("fexit/a", 11, 5, 110, Some(true)),
            abs("fexit/a", 13, 7, 120, Some(true)),
        ];
        let err = join_agg_miss_deltas(&baseline, &dup_section).expect_err("dup section");
        assert!(matches!(err, MissError::DuplicateSection { .. }), "{err:?}");
        let dup_id = vec![
            abs("fexit/a", 11, 5, 110, Some(true)),
            abs("fexit/b", 11, 2, 60, Some(true)),
        ];
        let err = join_agg_miss_deltas(&baseline, &dup_id).expect_err("dup id");
        assert!(matches!(err, MissError::DuplicateId { .. }), "{err:?}");
        // Shuffled clean inputs join by (section, id), not position.
        let shuffled = vec![
            abs("fexit/b", 12, 2, 60, Some(true)),
            abs("fexit/a", 11, 5, 110, Some(true)),
        ];
        let joined = join_agg_miss_deltas(&baseline, &shuffled).expect("shuffled joins");
        assert_eq!(joined.len(), 2);
        assert_eq!(joined[0].section, "fexit/b");
        assert_eq!(joined[0].miss_delta, 2);
        assert_eq!(joined[0].run_delta, Some(10));
    }

    #[test]
    fn counter_reset_is_not_zero_loss() {
        // A current below its baseline (either counter) refuses —
        // never a zero (or wrapped) delta.
        let baseline = vec![abs("fexit/a", 11, 30, 100, Some(true))];
        let back_misses = vec![abs("fexit/a", 11, 3, 200, Some(true))];
        let err = join_agg_miss_deltas(&baseline, &back_misses).expect_err("miss reset");
        assert!(matches!(err, MissError::Reset { .. }), "{err:?}");
        let back_run = vec![abs("fexit/a", 11, 31, 40, Some(true))];
        let err = join_agg_miss_deltas(&baseline, &back_run).expect_err("run reset");
        assert!(matches!(err, MissError::Reset { .. }), "{err:?}");
    }

    #[test]
    fn miss_saturated_absolute_refuses() {
        // A MAX absolute (either counter, either endpoint) already
        // saturated — refuse per ADR-0008 §(e), never sum it.
        let baseline = vec![abs("fexit/a", 11, 3, 100, Some(true))];
        for poison in [
            abs("fexit/a", 11, u64::MAX, 200, Some(true)),
            abs("fexit/a", 11, 9, u64::MAX, Some(true)),
        ] {
            let err = join_agg_miss_deltas(&baseline, &[poison]).expect_err("saturated refuses");
            assert!(matches!(err, MissError::Saturated { .. }), "{err:?}");
        }
        let max_base = vec![abs("fexit/a", 11, u64::MAX, 100, Some(true))];
        let current = vec![abs("fexit/a", 11, u64::MAX, 200, Some(true))];
        let err = join_agg_miss_deltas(&max_base, &current).expect_err("max baseline");
        assert!(matches!(err, MissError::Saturated { .. }), "{err:?}");
    }

    #[test]
    fn miss_zero_delta_is_clean() {
        // A genuine zero (no skips, monotone, unsaturated) joins to a
        // clean zero delta — zeros from READ counters are valid; only
        // unreadable counters refuse.
        let baseline = vec![abs("fexit/a", 11, 0, 100, Some(true))];
        let current = vec![abs("fexit/a", 11, 0, 150, Some(true))];
        let joined = join_agg_miss_deltas(&baseline, &current).expect("zero joins");
        assert_eq!(joined[0].miss_delta, 0);
        assert_eq!(joined[0].run_delta, Some(50));
    }

    #[test]
    fn miss_stats_off_run_unavailable() {
        // Statistics off (or toggled, or unreadable) at either
        // endpoint: run deltas are NOT evidence (None), but the miss
        // delta still joins (misses need no enabling — I-NC64 leg0).
        let baseline = vec![abs("fexit/a", 11, 3, 0, Some(false))];
        let current = vec![abs("fexit/a", 11, 9, 0, Some(false))];
        let joined = join_agg_miss_deltas(&baseline, &current).expect("off joins");
        assert_eq!(joined[0].miss_delta, 6);
        assert_eq!(joined[0].run_delta, None);
        let toggled = vec![abs("fexit/a", 11, 9, 40, Some(true))];
        let joined = join_agg_miss_deltas(&baseline, &toggled).expect("toggled joins");
        assert_eq!(joined[0].miss_delta, 6);
        assert_eq!(joined[0].run_delta, None);
        let unknown = vec![abs("fexit/a", 11, 9, 40, None)];
        let joined = join_agg_miss_deltas(&baseline, &unknown).expect("unknown joins");
        assert_eq!(joined[0].run_delta, None);
    }

    #[test]
    fn miss_appeared_vanished_unarmed_refuse() {
        // Appeared / vanished / unarmed inputs refuse (bijection).
        let baseline = vec![abs("fexit/a", 11, 3, 100, Some(true))];
        let appeared = vec![
            abs("fexit/a", 11, 5, 110, Some(true)),
            abs("fexit/b", 12, 0, 10, Some(true)),
        ];
        let err = join_agg_miss_deltas(&baseline, &appeared).expect_err("appeared");
        assert!(matches!(err, MissError::Appeared { .. }), "{err:?}");
        let vanished: Vec<AggProgMissAbs> = vec![];
        let err = join_agg_miss_deltas(&baseline, &vanished).expect_err("vanished");
        assert!(matches!(err, MissError::Vanished { .. }), "{err:?}");
        let err = join_agg_miss_deltas(&[], &appeared[..1]).expect_err("unarmed");
        assert!(matches!(err, MissError::Unarmed), "{err:?}");
    }

    #[test]
    fn miss_reader_bad_fd_is_typed() {
        // The reader maps syscall failures to typed errors (never a
        // panic, never a zero): an inert FD refuses as GetInfo.
        use std::os::fd::IntoRawFd;
        let file = std::fs::File::open("/dev/null").expect("inert fd");
        // SAFETY: ownership transfers from File exactly once.
        let fd = unsafe { crate::fd::OwnedFd::from_raw_fd(file.into_raw_fd()) };
        let mut table = HashMap::new();
        table.insert(
            "kcrypto_skenc".to_owned(),
            "fexit/crypto_skcipher_encrypt".to_owned(),
        );
        let err = snapshot_agg_misses(&[("kcrypto_skenc".to_owned(), fd)], &table)
            .expect_err("bad fd refuses");
        assert!(matches!(err, MissError::GetInfo { .. }), "{err:?}");
    }

    #[test]
    fn miss_reader_unlabeled_name_refuses() {
        // A retained name with no section in the table refuses (never
        // a guessed label) — before any syscall.
        use std::os::fd::IntoRawFd;
        let file = std::fs::File::open("/dev/null").expect("inert fd");
        // SAFETY: ownership transfers from File exactly once.
        let fd = unsafe { crate::fd::OwnedFd::from_raw_fd(file.into_raw_fd()) };
        let table = HashMap::new();
        let err = snapshot_agg_misses(&[("mystery".to_owned(), fd)], &table)
            .expect_err("unlabeled refuses");
        assert!(matches!(err, MissError::Unlabeled { .. }), "{err:?}");
    }

    // F03/BPF1 interval oracles: scripted bring-up stages through the
    // REAL production sequencing (`run_bringup_with_baseline`) + the
    // REAL join + the REAL terminal mapping. The scripted "kernel" is
    // (misses, run_cnt, admitted): guard skips, accepted executions,
    // and the KTOT-like admitted count proving the window is real.
    type Scripted = std::cell::RefCell<(u64, u64, u64)>;

    fn scripted_abs(kernel: &Scripted, id: u32) -> AggProgMissAbs {
        let got = kernel.borrow();
        abs("fexit/scripted", id, got.0, got.1, Some(false))
    }

    #[test]
    fn bringup_misses_share_admission_interval() {
        // Five guard misses + seven known admitted calls injected
        // between first attach and end of setup (the BPF1 window),
        // with NO later misses (the finding's static model: early
        // misses only). Terminal output must count the five or
        // declare measurement unavailable — never measured zero.
        // (The pre-F03 attach-then-baseline order fails this: the
        // baseline read swallows the five and the join reports
        // measured 0.)
        let kernel = Scripted::new((0, 0, 0));
        let (sensor, baseline) = run_bringup_with_baseline(
            &kernel,
            |staged: &&Scripted| Some(vec![scripted_abs(staged, 41)]),
            |staged: &Scripted| -> Result<&Scripted, std::convert::Infallible> {
                // First attach: kernel crypto fires while remaining
                // setup runs — 5 guard misses + 7 admitted calls land
                // AFTER the pre-attach baseline, so the join counts
                // them.
                let mut got = staged.borrow_mut();
                got.0 += 5;
                got.1 += 7;
                got.2 += 7;
                Ok(staged)
            },
        )
        .expect("scripted bring-up");
        let current = vec![scripted_abs(sensor, 41)];
        // Non-vacuity: the window really admitted executions, so a
        // measured zero would contradict known activity.
        assert_eq!(sensor.borrow().2, 7, "window must admit known calls");
        let terminal = miss_terminal_from_join(join_agg_miss_deltas(
            baseline.as_ref().expect("baseline read"),
            &current,
        ));
        match terminal {
            MissTerminal::Available(deltas) => {
                let total: u64 = deltas.iter().map(|d| d.miss_delta).sum();
                assert_eq!(
                    total, 5,
                    "bring-up misses must be counted, got measured {total}"
                );
            }
            MissTerminal::Unavailable { reason } => assert!(!reason.is_empty()),
        }
    }

    #[test]
    fn bringup_no_miss_control_stays_clean() {
        // Control: zero misses in the window with admitted calls — a
        // TRUE zero from read counters stays Available (the fix must
        // not overcorrect into Unavailable).
        let kernel = Scripted::new((0, 0, 0));
        let (sensor, baseline) = run_bringup_with_baseline(
            &kernel,
            |staged: &&Scripted| Some(vec![scripted_abs(staged, 41)]),
            |staged: &Scripted| -> Result<&Scripted, std::convert::Infallible> {
                staged.borrow_mut().2 += 7;
                staged.borrow_mut().1 += 7;
                Ok(staged)
            },
        )
        .expect("scripted bring-up");
        let current = vec![scripted_abs(sensor, 41)];
        assert_eq!(sensor.borrow().2, 7, "window must admit known calls");
        let terminal = miss_terminal_from_join(join_agg_miss_deltas(
            baseline.as_ref().expect("baseline read"),
            &current,
        ));
        match terminal {
            MissTerminal::Available(deltas) => {
                let total: u64 = deltas.iter().map(|d| d.miss_delta).sum();
                assert_eq!(total, 0, "true zero stays a clean zero");
            }
            MissTerminal::Unavailable { reason } => {
                panic!("true zero must stay Available, got unavailable: {reason}")
            }
        }
    }

    #[test]
    fn bringup_program_replacement_is_unavailable() {
        // Control: program replaced between baseline and current (id
        // 41 -> 42) — the join refuses and the terminal reads
        // Unavailable through the shared production mapping, never
        // zero.
        let baseline = vec![abs("fexit/scripted", 41, 0, 0, Some(false))];
        let current = vec![abs("fexit/scripted", 42, 5, 7, Some(false))];
        let terminal = miss_terminal_from_join(join_agg_miss_deltas(&baseline, &current));
        match terminal {
            MissTerminal::Available(deltas) => {
                panic!("replacement must refuse, got {deltas:?}")
            }
            MissTerminal::Unavailable { reason } => {
                assert!(reason.contains("replaced"), "reason names it: {reason}")
            }
        }
    }

    #[test]
    fn bringup_unreadable_baseline_is_unavailable() {
        // Control: baseline read refused (the GET_INFO errno path) —
        // a missing baseline is explicit unavailability through the
        // shared production arm, never measured zero.
        let kernel = Scripted::new((0, 0, 0));
        let (_sensor, baseline) = run_bringup_with_baseline(
            &kernel,
            |_staged: &&Scripted| None,
            |staged: &Scripted| -> Result<&Scripted, std::convert::Infallible> {
                let mut got = staged.borrow_mut();
                got.0 += 5;
                got.2 += 7;
                Ok(staged)
            },
        )
        .expect("scripted bring-up");
        assert!(baseline.is_none(), "unreadable baseline stays None");
        let terminal = miss_terminal_no_baseline();
        match terminal {
            MissTerminal::Available(deltas) => {
                panic!("missing baseline must not join, got {deltas:?}")
            }
            MissTerminal::Unavailable { reason } => {
                assert!(reason.contains("baseline"), "reason names it: {reason}")
            }
        }
    }
}
