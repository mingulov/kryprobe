// SPDX-License-Identifier: GPL-3.0-or-later
//! Sensor identity: GET_INFO snapshots + baseline verification (M2).
//!
//! [`SensorIdentity::snapshot`] reads every program, map, and link fd
//! through raw `BPF_OBJ_GET_INFO_BY_FD` (never fdinfo — the 4-model
//! consensus), validating the returned `info_len` covers each field
//! consumed. The sensor snapshots pre-arm (baseline) and re-verifies
//! after ingest; any mismatch flips the sticky validity off. Misses
//! are coverage (they void exact counts — see the ledger's
//! `view_valid`); pairing never consults them.

use crate::attach::OwnedLink;
use crate::bpfloader::{LifecycleMaps, LoadedLifecycle};
use crate::kcrypto_lifecycle::profile::LIFECYCLE_MAPS;
use crate::probe::bpf_sys::{BPF_LINK_TYPE_TRACING, BPF_PROG_TYPE_TRACING, obj_get_info};
use std::os::fd::RawFd;

/// Info buffer: 512 zeroed bytes hold any current
/// `bpf_prog/map/link_info` (the kernel copies `min(in, struct)` and
/// reports its full size — oversize is forward-compatible, and every
/// consumed prefix is length-checked).
const INFO_BUF: usize = 512;

/// Consumed `bpf_prog_info` prefix: `type`@0, `id`@4, `name`@64..80.
const PROG_PREFIX: u32 = 80;
/// Consumed `bpf_prog_info` prefix for recursion-miss reads (H2):
/// everything above through `recursion_misses`@208..216 (`run_time_ns`@192,
/// `run_cnt`@200, `recursion_misses`@208 per the 7.0 UAPI layout —
/// misses are coverage, read separately from identity, never pinned).
const PROG_MISS_PREFIX: u32 = 216;
/// `recursion_misses` offset in `bpf_prog_info` (7.0 UAPI).
const RECURSION_MISSES_OFF: usize = 208;
/// Consumed `bpf_map_info` prefix: type/id/key/value/max@0..20.
const MAP_PREFIX: u32 = 20;
/// Consumed `bpf_link_info` prefix: type/id/prog_id@0..12 +
/// `tracing.attach_type/target_btf_id`@12..24.
const LINK_PREFIX: u32 = 24;

/// Identity verification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewError {
    /// `BPF_OBJ_GET_INFO_BY_FD` refused.
    GetInfo {
        /// Which object (`prog`/`map`/`link` + name).
        stage: String,
        /// Kernel errno.
        errno: i32,
    },
    /// Kernel struct shorter than the consumed prefix (ancient or
    /// future kernel — refuse, never read past the report).
    InfoShort {
        /// Which object.
        stage: String,
        /// Reported struct length.
        got: u32,
        /// Required prefix length.
        want: u32,
    },
    /// Identity mismatch (wrong type, drifted dims, id moved, a
    /// link that no longer names our program, or a per-program
    /// miss-counter join the kernel made untrustworthy: backwards,
    /// unbaselined, or vanished mid-session).
    Identity {
        /// What mismatched (names + values, never raw pointers).
        detail: String,
    },
}

impl std::fmt::Display for ViewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GetInfo { stage, errno } => {
                write!(
                    f,
                    "sensor identity: GET_INFO for {stage} failed: errno {errno}"
                )
            }
            Self::InfoShort { stage, got, want } => {
                write!(
                    f,
                    "sensor identity: {stage} info length {got} below prefix {want}"
                )
            }
            Self::Identity { detail } => write!(f, "sensor identity: {detail}"),
        }
    }
}

impl std::error::Error for ViewError {}

fn u32le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn u64le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

fn info_for(fd: RawFd, stage: &str, want: u32) -> Result<[u8; INFO_BUF], ViewError> {
    let mut buf = [0u8; INFO_BUF];
    let got = obj_get_info(fd, &mut buf).map_err(|errno| ViewError::GetInfo {
        stage: stage.to_owned(),
        errno,
    })?;
    if got < want {
        return Err(ViewError::InfoShort {
            stage: stage.to_owned(),
            got,
            want,
        });
    }
    Ok(buf)
}

/// Program identity: kernel id + load-time name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgIdentity {
    /// Section (our label for the program).
    pub section: String,
    /// Kernel program id.
    pub id: u32,
    /// Load-time program name (baseline-compared, never pinned).
    pub name: String,
}

/// Map identity: kernel id + pinned dims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapIdentity {
    /// Manifest map name (`LCFG`, `LRING`, ...).
    pub name: String,
    /// Kernel map id.
    pub id: u32,
    /// Kernel map type (pinned vs the manifest).
    pub map_type: u32,
    /// Kernel key size (pinned vs the manifest).
    pub key_size: u32,
    /// Kernel value size (pinned vs the manifest).
    pub value_size: u32,
    /// Kernel max entries (pinned vs the manifest).
    pub max_entries: u32,
}

/// Link identity: kernel id + attach shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkIdentity {
    /// Attached section (our label for the link).
    pub section: String,
    /// Kernel link id.
    pub id: u32,
    /// Linked program id (must name our program).
    pub prog_id: u32,
    /// Reported link attach type (baseline-compared, never pinned:
    /// 7.0.14 reports 0 for fsession links despite `LINK_CREATE`
    /// carrying 58 — the program's load-time `expected_attach_type`
    /// is the enforced pin, the link report is monitored drift).
    pub attach_type: u32,
    /// Attach BTF id (baseline-compared, never pinned: the kernel
    /// resolves it at load).
    pub target_btf_id: u32,
}

/// Whole-sensor identity snapshot (one per sensor lifetime baseline +
/// one per verification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorIdentity {
    /// Program identities in load order.
    pub progs: Vec<ProgIdentity>,
    /// Map identities in manifest order.
    pub maps: Vec<MapIdentity>,
    /// Link identities in attach order.
    pub links: Vec<LinkIdentity>,
}

impl SensorIdentity {
    /// Snapshot every program, map, and link fd: absolute pins (prog
    /// type `TRACING`, link type `TRACING`, map dims vs the frozen
    /// manifest, every link naming our program) hold HERE — a fresh
    /// sensor whose fds fail them never arms. The link attach type
    /// and target BTF id are recorded for baseline comparison, not
    /// pinned (7.0.14 reports attach 0 for fsession links).
    pub fn snapshot(
        loaded: &LoadedLifecycle,
        links: &[(String, OwnedLink)],
    ) -> Result<Self, ViewError> {
        let mut progs = Vec::with_capacity(loaded.progs.len());
        for (section, fd) in &loaded.progs {
            let stage = format!("prog {section}");
            let buf = info_for(fd.as_raw_fd(), &stage, PROG_PREFIX)?;
            if u32le(&buf, 0) != BPF_PROG_TYPE_TRACING {
                return Err(ViewError::Identity {
                    detail: format!("{stage}: prog type {} is not TRACING", u32le(&buf, 0)),
                });
            }
            let raw = &buf[64..80];
            let len = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            progs.push(ProgIdentity {
                section: section.clone(),
                id: u32le(&buf, 4),
                name: String::from_utf8_lossy(&raw[..len]).into_owned(),
            });
        }
        let maps = snapshot_maps(&loaded.maps)?;
        let mut out = Vec::with_capacity(links.len());
        for (section, link) in links {
            let stage = format!("link {section}");
            let buf = info_for(link.as_raw_fd(), &stage, LINK_PREFIX)?;
            if u32le(&buf, 0) != BPF_LINK_TYPE_TRACING {
                return Err(ViewError::Identity {
                    detail: format!("{stage}: link type {} is not TRACING", u32le(&buf, 0)),
                });
            }
            let prog_id = u32le(&buf, 8);
            if !progs
                .iter()
                .any(|p| p.section == *section && p.id == prog_id)
            {
                return Err(ViewError::Identity {
                    detail: format!("{stage}: link names foreign prog id {prog_id}"),
                });
            }
            out.push(LinkIdentity {
                section: section.clone(),
                id: u32le(&buf, 4),
                prog_id,
                attach_type: u32le(&buf, 12),
                target_btf_id: u32le(&buf, 20),
            });
        }
        Ok(Self {
            progs,
            maps,
            links: out,
        })
    }

    /// Re-verify against the pre-arm baseline: same cardinality, same
    /// kernel ids, same names, same dims, same attach shape. Kernel
    /// ids never move for a live object — any drift proves fd mixup
    /// or object replacement, and the sensor's sticky validity dies.
    pub fn verify_against(&self, baseline: &Self) -> Result<(), ViewError> {
        if self.progs.len() != baseline.progs.len()
            || self.maps.len() != baseline.maps.len()
            || self.links.len() != baseline.links.len()
        {
            return Err(ViewError::Identity {
                detail: format!(
                    "cardinality moved (progs {}/{}, maps {}/{}, links {}/{})",
                    self.progs.len(),
                    baseline.progs.len(),
                    self.maps.len(),
                    baseline.maps.len(),
                    self.links.len(),
                    baseline.links.len(),
                ),
            });
        }
        for (got, want) in self.progs.iter().zip(baseline.progs.iter()) {
            if got != want {
                return Err(ViewError::Identity {
                    detail: format!("prog identity moved (was {want:?}, is {got:?})"),
                });
            }
        }
        for (got, want) in self.maps.iter().zip(baseline.maps.iter()) {
            if got != want {
                return Err(ViewError::Identity {
                    detail: format!("map identity moved (was {want:?}, is {got:?})"),
                });
            }
        }
        for (got, want) in self.links.iter().zip(baseline.links.iter()) {
            if got != want {
                return Err(ViewError::Identity {
                    detail: format!("link identity moved (was {want:?}, is {got:?})"),
                });
            }
        }
        Ok(())
    }

    /// Re-verify after detach (links dropped by design): progs + maps
    /// must still match, the link set must be EMPTY (a surviving
    /// link post-detach is a leak — invalid), and the baseline must
    /// have carried links (an empty baseline never armed).
    pub fn verify_detached(&self, baseline: &Self) -> Result<(), ViewError> {
        if baseline.links.is_empty() {
            return Err(ViewError::Identity {
                detail: "baseline carries no links — the sensor never armed".to_owned(),
            });
        }
        if !self.links.is_empty() {
            return Err(ViewError::Identity {
                detail: format!("{} links survive detach (leak)", self.links.len()),
            });
        }
        if self.progs.len() != baseline.progs.len() || self.maps.len() != baseline.maps.len() {
            return Err(ViewError::Identity {
                detail: format!(
                    "cardinality moved post-detach (progs {}/{}, maps {}/{})",
                    self.progs.len(),
                    baseline.progs.len(),
                    self.maps.len(),
                    baseline.maps.len(),
                ),
            });
        }
        for (got, want) in self.progs.iter().zip(baseline.progs.iter()) {
            if got != want {
                return Err(ViewError::Identity {
                    detail: format!("prog identity moved (was {want:?}, is {got:?})"),
                });
            }
        }
        for (got, want) in self.maps.iter().zip(baseline.maps.iter()) {
            if got != want {
                return Err(ViewError::Identity {
                    detail: format!("map identity moved (was {want:?}, is {got:?})"),
                });
            }
        }
        Ok(())
    }
}

/// Per-program recursion-miss absolute (H2 coverage, NOT identity:
/// the counter legitimately moves, so it never joins
/// [`SensorIdentity::verify_against`] — misses void exact counts, they
/// never void identity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgMisses {
    /// Section (our label for the program — the join key).
    pub section: String,
    /// Kernel program id (join audit: must match the identity read).
    pub id: u32,
    /// Absolute `recursion_misses` at read time.
    pub misses: u64,
}

/// Per-program miss abs+delta (receipts report all three; gates void
/// on a nonzero delta).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgMissDelta {
    /// Section (join key).
    pub section: String,
    /// Pre-arm absolute.
    pub baseline: u64,
    /// Post-ingest absolute.
    pub current: u64,
}

impl ProgMissDelta {
    /// Session-attributable misses. A backwards counter (current
    /// below baseline — counter replacement under a retained FD,
    /// impossible without kernel foul play) voids LOUD: it reads
    /// `u64::MAX`, never zero, so a hand-built backwards delta still
    /// flips every void channel it reaches. The checked join refuses
    /// these before they reach a ledger; this arm guards direct
    /// construction only.
    #[must_use]
    pub fn delta(&self) -> u64 {
        self.current.checked_sub(self.baseline).unwrap_or(u64::MAX)
    }
}

/// Snapshot every program's `recursion_misses` absolute (H2 "read
/// after ingest" twin of [`SensorIdentity::snapshot`]): same
/// `BPF_OBJ_GET_INFO_BY_FD` path, same TRACING pin, deeper prefix
/// (`PROG_MISS_PREFIX` covers `recursion_misses`@208). A short report
/// refuses (ancient kernel — never read past it) and a failed GET_INFO
/// fails the read (the ledger fails loud — an unreadable miss counter
/// must never read as zero).
pub fn snapshot_prog_misses(loaded: &LoadedLifecycle) -> Result<Vec<ProgMisses>, ViewError> {
    let mut out = Vec::with_capacity(loaded.progs.len());
    for (section, fd) in &loaded.progs {
        let stage = format!("prog {section}");
        let buf = info_for(fd.as_raw_fd(), &stage, PROG_MISS_PREFIX)?;
        if u32le(&buf, 0) != BPF_PROG_TYPE_TRACING {
            return Err(ViewError::Identity {
                detail: format!("{stage}: prog type {} is not TRACING", u32le(&buf, 0)),
            });
        }
        out.push(ProgMisses {
            section: section.clone(),
            id: u32le(&buf, 4),
            misses: u64le(&buf, RECURSION_MISSES_OFF),
        });
    }
    Ok(out)
}

/// Join pre-arm and post-ingest miss absolutes by section (pure —
/// unit-tested without privilege; the one production join site feeds
/// `SensorCore::ledger`, which fails the terminal ledger on
/// refusal). Every section must appear on BOTH sides with a monotone
/// counter — a current below its baseline (counter replacement), a
/// current section with no baseline (program appeared mid-session),
/// or a baseline section gone from current (program vanished
/// mid-session) REFUSES with [`ViewError::Identity`]: an
/// untrustworthy miss join fails loud, never reads zero. (With
/// retained FDs all three are kernel impossibilities; the refusal
/// arm is fail-closed hardening, and the appeared/vanished cases
/// additionally void identity.)
pub fn join_miss_deltas(
    baseline: &[ProgMisses],
    current: &[ProgMisses],
) -> Result<Vec<ProgMissDelta>, ViewError> {
    let mut out = Vec::with_capacity(current.len());
    for got in current {
        let Some(want) = baseline.iter().find(|want| want.section == got.section) else {
            return Err(ViewError::Identity {
                detail: format!("prog_misses[{}] has no baseline", got.section),
            });
        };
        if got.misses < want.misses {
            return Err(ViewError::Identity {
                detail: format!(
                    "prog_misses[{}] ran backwards: baseline {} current {}",
                    got.section, want.misses, got.misses
                ),
            });
        }
        out.push(ProgMissDelta {
            section: got.section.clone(),
            baseline: want.misses,
            current: got.misses,
        });
    }
    for want in baseline {
        if !current.iter().any(|got| got.section == want.section) {
            return Err(ViewError::Identity {
                detail: format!("prog_misses[{}] baseline has no current", want.section),
            });
        }
    }
    Ok(out)
}

/// Session miss total over joined deltas (saturating — the coverage
/// gate's input: any nonzero voids exact counts, and a backwards
/// delta voids `u64::MAX`, never zero).
#[must_use]
pub fn prog_miss_delta_sum(deltas: &[ProgMissDelta]) -> u64 {
    deltas
        .iter()
        .fold(0u64, |sum, delta| sum.saturating_add(delta.delta()))
}

fn snapshot_maps(maps: &LifecycleMaps) -> Result<Vec<MapIdentity>, ViewError> {
    use crate::fd::OwnedFd;
    let named: &[(&str, &OwnedFd)] = &[
        ("LCFG", &maps.config),
        ("LRING", &maps.ring),
        ("LLOSS", &maps.loss),
        ("LAGG", &maps.agg),
        ("LCTR", &maps.ctr),
    ];
    let mut out = Vec::with_capacity(named.len());
    for (name, fd) in named {
        let stage = format!("map {name}");
        let buf = info_for(fd.as_raw_fd(), &stage, MAP_PREFIX)?;
        let dims = LIFECYCLE_MAPS
            .iter()
            .find(|(n, _)| *n == *name)
            .map(|(_, d)| d)
            .expect("manifest carries every lifecycle map");
        let (map_type, key_size, value_size, max_entries) = (
            u32le(&buf, 0),
            u32le(&buf, 8),
            u32le(&buf, 12),
            u32le(&buf, 16),
        );
        if map_type != dims.map_type
            || key_size != dims.key_size
            || value_size != dims.value_size
            || max_entries != dims.max_entries
        {
            return Err(ViewError::Identity {
                detail: format!(
                    "{stage}: dims {map_type}:{key_size}:{value_size}:{max_entries} != manifest {}:{}:{}:{}",
                    dims.map_type, dims.key_size, dims.value_size, dims.max_entries
                ),
            });
        }
        out.push(MapIdentity {
            name: name.to_string(),
            id: u32le(&buf, 4),
            map_type,
            key_size,
            value_size,
            max_entries,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::bpf_sys::BPF_TRACE_FSESSION;

    fn prog(section: &str, id: u32, name: &str) -> ProgIdentity {
        ProgIdentity {
            section: section.to_owned(),
            id,
            name: name.to_owned(),
        }
    }

    fn map(name: &str, id: u32) -> MapIdentity {
        MapIdentity {
            name: name.to_owned(),
            id,
            map_type: 6,
            key_size: 4,
            value_size: 8,
            max_entries: 20,
        }
    }

    fn link(section: &str, id: u32, prog_id: u32, target: u32) -> LinkIdentity {
        LinkIdentity {
            section: section.to_owned(),
            id,
            prog_id,
            attach_type: BPF_TRACE_FSESSION,
            target_btf_id: target,
        }
    }

    fn identity() -> SensorIdentity {
        SensorIdentity {
            progs: vec![prog("fsession/a", 11, "prog_a")],
            maps: vec![map("LLOSS", 12)],
            links: vec![link("fsession/a", 13, 11, 700)],
        }
    }

    #[test]
    fn identical_verifies() {
        identity()
            .verify_against(&identity())
            .expect("identical verifies");
    }

    fn misses(section: &str, id: u32, misses: u64) -> ProgMisses {
        ProgMisses {
            section: section.to_owned(),
            id,
            misses,
        }
    }

    #[test]
    fn miss_prefix_covers_recursion_misses() {
        // The 216-byte prefix must cover misses@208..216 inside the
        // 512-byte info buffer (a short prefix would refuse every
        // 7.0 kernel via InfoShort).
        assert!(RECURSION_MISSES_OFF + 8 <= PROG_MISS_PREFIX as usize);
        assert!(PROG_MISS_PREFIX as usize <= INFO_BUF);
        assert_eq!(RECURSION_MISSES_OFF, 208);
    }

    #[test]
    fn u64le_reads_little_endian() {
        let mut buf = [0u8; 216];
        buf[208..216].copy_from_slice(&0x0102030405060708u64.to_le_bytes());
        assert_eq!(u64le(&buf, 208), 0x0102030405060708);
    }

    #[test]
    fn join_deltas_by_section() {
        let baseline = vec![misses("fsession/a", 11, 3), misses("fsession/b", 12, 0)];
        let current = vec![misses("fsession/b", 12, 2), misses("fsession/a", 11, 5)];
        let joined = join_miss_deltas(&baseline, &current).expect("monotone join");
        assert_eq!(
            joined,
            vec![
                ProgMissDelta {
                    section: "fsession/b".to_owned(),
                    baseline: 0,
                    current: 2,
                },
                ProgMissDelta {
                    section: "fsession/a".to_owned(),
                    baseline: 3,
                    current: 5,
                },
            ]
        );
        assert_eq!(joined[0].delta(), 2);
        assert_eq!(joined[1].delta(), 2);
        assert_eq!(prog_miss_delta_sum(&joined), 4);
    }

    #[test]
    fn join_unbaselined_section_refuses() {
        // W10: a program that appeared mid-session (identity already
        // void on cardinality) refuses the join — an unbaselined
        // current fails loud, never reads zero.
        let err = join_miss_deltas(&[], &[misses("fsession/a", 11, 7)])
            .expect_err("unbaselined current must refuse");
        assert!(matches!(err, ViewError::Identity { .. }), "{err:?}");
    }

    #[test]
    fn join_vanished_baseline_section_refuses() {
        // W10: a baseline section gone from current (program
        // vanished mid-session) refuses — dropped sections must fail
        // loud, never read zero.
        let baseline = vec![misses("fsession/a", 11, 3)];
        let err = join_miss_deltas(&baseline, &[]).expect_err("vanished baseline must refuse");
        assert!(matches!(err, ViewError::Identity { .. }), "{err:?}");
    }

    #[test]
    fn join_backwards_counter_refuses() {
        // W10: a current below its baseline (counter replacement)
        // refuses — backwards counters fail loud, never read zero.
        let baseline = vec![misses("fsession/a", 11, 9)];
        let current = vec![misses("fsession/a", 11, 4)];
        let err = join_miss_deltas(&baseline, &current).expect_err("backwards must refuse");
        assert!(matches!(err, ViewError::Identity { .. }), "{err:?}");
    }

    #[test]
    fn delta_backwards_voids_loud_never_zero() {
        // W10: the checked join refuses backwards counters before
        // they reach a ledger; a hand-built backwards delta still
        // voids MAX (never zero) through every consumer it reaches.
        let back = ProgMissDelta {
            section: "fsession/a".to_owned(),
            baseline: 9,
            current: 4,
        };
        assert_eq!(back.delta(), u64::MAX);
        assert_eq!(prog_miss_delta_sum(&[back]), u64::MAX);
        let sat = ProgMissDelta {
            section: "fsession/a".to_owned(),
            baseline: 0,
            current: u64::MAX,
        };
        let one = ProgMissDelta {
            section: "fsession/b".to_owned(),
            baseline: 0,
            current: 1,
        };
        assert_eq!(prog_miss_delta_sum(&[sat, one]), u64::MAX);
    }

    #[test]
    fn moved_prog_id_fails() {
        let mut got = identity();
        got.progs[0].id = 99;
        let err = got.verify_against(&identity()).expect_err("must refuse");
        assert!(matches!(err, ViewError::Identity { .. }), "{err:?}");
    }

    #[test]
    fn moved_map_dims_fail() {
        let mut got = identity();
        got.maps[0].max_entries = 21;
        let err = got.verify_against(&identity()).expect_err("must refuse");
        assert!(matches!(err, ViewError::Identity { .. }), "{err:?}");
    }

    #[test]
    fn moved_link_target_fails() {
        let mut got = identity();
        got.links[0].target_btf_id = 701;
        let err = got.verify_against(&identity()).expect_err("must refuse");
        assert!(matches!(err, ViewError::Identity { .. }), "{err:?}");
    }

    #[test]
    fn dropped_link_fails() {
        let mut got = identity();
        got.links.clear();
        let err = got.verify_against(&identity()).expect_err("must refuse");
        assert!(matches!(err, ViewError::Identity { .. }), "{err:?}");
    }

    #[test]
    fn detached_verifies_progs_maps_and_empty_links() {
        // Post-detach: same progs+maps, no links → verifies.
        let mut got = identity();
        got.links.clear();
        got.verify_detached(&identity()).expect("detached verifies");
        // A surviving link post-detach is a leak → invalid.
        let err = identity()
            .verify_detached(&identity())
            .expect_err("must refuse");
        assert!(matches!(err, ViewError::Identity { .. }), "{err:?}");
        // A moved prog post-detach still fails.
        let mut moved = identity();
        moved.links.clear();
        moved.progs[0].id = 99;
        let err = moved.verify_detached(&identity()).expect_err("must refuse");
        assert!(matches!(err, ViewError::Identity { .. }), "{err:?}");
        // An empty baseline never armed → invalid.
        let empty = SensorIdentity {
            progs: vec![],
            maps: vec![],
            links: vec![],
        };
        let err = empty.verify_detached(&empty).expect_err("must refuse");
        assert!(matches!(err, ViewError::Identity { .. }), "{err:?}");
    }
}
