// SPDX-License-Identifier: GPL-3.0-or-later
//! Lifecycle sensor: one owner, one drain, one terminal ledger (T06).
//!
//! [`SensorCore`] is the pure ingest path (ring records → decode →
//! reducer → completed records), unit-tested without privilege.
//! [`LifecycleSensor`] wraps it with the configured kernel sensor and
//! the mmap'd ring; `drain_once` is the single drain. The terminal
//! ledger ([`LifecycleLedger`]) is the single place completed records
//! and loss meet: kernel `LLOSS` counters + decode stats + reducer
//! stats, snapshotted together.

use crate::btf_resolve::{ConfiguredError, ConfiguredPoint};
use crate::drain::DrainError;
use crate::drain::area::RingArea;
use crate::kcrypto_lifecycle::decode::{DecodeStats, LifecycleDecoder, decode_record};
use crate::kcrypto_lifecycle::proc_crypto::{ProcCryptoSnapshot, snapshot_proc_crypto};
use crate::kcrypto_lifecycle::profile::{
    LIFECYCLE_MAPS, LLOSS_ENTRIES, LLOSS_LANES_PER_CLASS, LifecycleProfile, SessionGuard,
    acquire_kcrypto_session,
};
use crate::kcrypto_lifecycle::tfm::{
    GenerationInfo, TfmStats, TransformTracker, decode_tfm_record, is_tfm_record,
};
use crate::kcrypto_lifecycle::view::{
    ProgMissDelta, ProgMisses, SensorIdentity, join_miss_deltas, snapshot_prog_misses,
};
use crate::kcrypto_lifecycle::{
    ConfiguredLifecycle, arm_lifecycle_config, disarm_lifecycle_config, load_lifecycle_configured,
};
use crate::mapops::{MapOpsError, map_lookup_percpu_sum};
use kryprobe_abi::kcrypto_lifecycle::{
    LAGG_ALLOCSK_RET, LAGG_ALLOCSK_SUB, LAGG_DESTROY_RET, LAGG_DESTROY_SUB, LAGG_SETAUTH_RET,
    LAGG_SETAUTH_SUB, LAGG_SETKEYAEAD_RET, LAGG_SETKEYAEAD_SUB, LAGG_SETKEYSK_RET,
    LAGG_SETKEYSK_SUB, LEDGE_RETURN, LEDGE_SUBMIT, LSITE_DEC, LTFM_SITE_ALLOC_SK,
    LTFM_SITE_DESTROY, LTFM_SITE_SETAUTHSIZE, LTFM_SITE_SETKEY_AEAD, LTFM_SITE_SETKEY_SK,
};
use kryprobe_core::kcrypto::{LifecycleReducer, ReducerStats, RequestRecord};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

/// Tally slot for a validated raw op edge: `[enc-submit, enc-return,
/// dec-submit, dec-return]` (lanes 0–3 of the 16-wide tally).
/// Validated inputs only (`decode_record` guarantees site ∈ {enc,
/// dec} and edge ∈ {submit, return}).
fn edge_slot(site: u16, edge: u8) -> usize {
    let site_idx = u16::from(site == LSITE_DEC);
    let edge_idx = u16::from(edge == LEDGE_RETURN);
    (site_idx * 2 + edge_idx) as usize
}

/// Tally slot for a validated raw transform edge: the `LAGG_*` hook
/// lane the BPF program bumped (T07.2 alloc-sk submit/return on
/// lanes 4–5; T07.3 destroy submit/return on lanes 6–7; T07.4
/// setkey-sk on lanes 8–9, setauthsize on lanes 10–11, setkey-aead
/// on lanes 14–15). Validated inputs only (`decode_tfm_record`
/// guarantees the site/edge shape).
fn tfm_slot(site: u16, edge: u8) -> usize {
    debug_assert!(
        site == LTFM_SITE_ALLOC_SK
            || site == LTFM_SITE_DESTROY
            || site == LTFM_SITE_SETKEY_SK
            || site == LTFM_SITE_SETAUTHSIZE
            || site == LTFM_SITE_SETKEY_AEAD
    );
    let ret = edge == LEDGE_RETURN;
    if site == LTFM_SITE_DESTROY {
        if ret {
            LAGG_DESTROY_RET as usize
        } else {
            LAGG_DESTROY_SUB as usize
        }
    } else if site == LTFM_SITE_SETKEY_SK {
        if ret {
            LAGG_SETKEYSK_RET as usize
        } else {
            LAGG_SETKEYSK_SUB as usize
        }
    } else if site == LTFM_SITE_SETAUTHSIZE {
        if ret {
            LAGG_SETAUTH_RET as usize
        } else {
            LAGG_SETAUTH_SUB as usize
        }
    } else if site == LTFM_SITE_SETKEY_AEAD {
        if ret {
            LAGG_SETKEYAEAD_RET as usize
        } else {
            LAGG_SETKEYAEAD_SUB as usize
        }
    } else if ret {
        LAGG_ALLOCSK_RET as usize
    } else {
        LAGG_ALLOCSK_SUB as usize
    }
}

/// `LRING` size (single source: the profile manifest's frozen dims).
fn ring_max() -> usize {
    LIFECYCLE_MAPS
        .iter()
        .find(|(name, _)| *name == "LRING")
        .map(|(_, dims)| dims.max_entries as usize)
        .expect("manifest carries LRING")
}

/// Fold the 80 per-(class, hook) `LLOSS` lanes into 5 per-class
/// totals (round-7 W7: one lane per hook per class, since an
/// interrupt can run a different program on the same CPU mid-bump).
/// Saturating — a saturated lane must not wrap the ledger.
#[must_use]
pub fn fold_loss_lanes(lanes: [u64; LLOSS_ENTRIES as usize]) -> [u64; 5] {
    let mut out = [0u64; 5];
    for (class, slot) in out.iter_mut().enumerate() {
        let base = class * LLOSS_LANES_PER_CLASS as usize;
        let mut total = 0u64;
        for lane in 0..LLOSS_LANES_PER_CLASS as usize {
            total = total.saturating_add(lanes[base + lane]);
        }
        *slot = total;
    }
    out
}

/// Read `LLOSS` per-class totals + `LAGG` per-hook accepted totals
/// (shared by the pre-arm baseline and every ledger snapshot).
fn read_kernel_counters(
    configured: &ConfiguredLifecycle,
) -> Result<([u64; 5], [u64; 16]), MapOpsError> {
    let mut lanes = [0u64; LLOSS_ENTRIES as usize];
    for (idx, slot) in lanes.iter_mut().enumerate() {
        *slot = map_lookup_percpu_sum(
            &configured.loaded.maps.loss,
            idx as u32,
            "lifecycle_sensor/lloss",
        )?;
    }
    let mut agg_accepted = [0u64; 16];
    for (idx, slot) in agg_accepted.iter_mut().enumerate() {
        *slot = map_lookup_percpu_sum(
            &configured.loaded.maps.agg,
            idx as u32,
            "lifecycle_sensor/lagg",
        )?;
    }
    Ok((fold_loss_lanes(lanes), agg_accepted))
}

/// Registry-enrichment status (T07-09: the terminal ledger tells
/// absent enrichment from an available snapshot — a failed
/// startup read never refuses capture, but its report carries
/// the reason, never silence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrichmentStatus {
    /// Bring-up snapshotted `/proc/crypto` (entry count +
    /// whether the snapshot hit a bound — current inventory
    /// only, never proof of what an earlier allocation used).
    Available {
        /// Registry blocks inventoried.
        entries: usize,
        /// The snapshot hit a parse bound (partial inventory).
        truncated: bool,
    },
    /// Bring-up could not snapshot `/proc/crypto` (capture
    /// proceeded without enrichment — the reason is the `io`
    /// error text, never a fabricated inventory).
    Unavailable {
        /// Why the snapshot failed.
        reason: String,
    },
}

/// Terminal ledger: completed records plus every loss class,
/// snapshotted together (the single terminal accounting point).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleLedger {
    /// Completed request records (grounded + truthless-drained).
    pub completed: Vec<RequestRecord>,
    /// Per-hook raw-edge hits in `LAGG_*` lane order (lanes 0–3
    /// are the op hooks `[enc-submit, enc-return, dec-submit,
    /// dec-return]` — the VM gate's "post-GO event per required
    /// hook"; lanes 4+ are the transform hooks as their halves land).
    pub edge_hits: [u64; 16],
    /// Decode loss counters.
    pub decode: DecodeStats,
    /// Reducer counters.
    pub reducer: ReducerStats,
    /// Kernel `LLOSS` per-class totals
    /// (reserve/disabled/badkey/fret/noslot).
    pub kernel_loss: [u64; 5],
    /// Kernel `LAGG` per-hook accepted totals in `LAGG_*` lane
    /// order (post-gate, pre-reserve). After a quiet drain with an
    /// empty close ring, `sum(agg_accepted) == sum(edge_hits) +
    /// kernel_loss[RESERVE] + kernel_loss[NOSLOT]` exactly — the
    /// reconciliation equation (the canary asserts it; `LAGG` bumps
    /// before the invocation issue, so NOSLOT drops count as
    /// accepted-but-untransported).
    pub agg_accepted: [u64; 16],
    /// Completions dropped from retention past the ledger bound
    /// (explicit loss; a draining reader never drops).
    pub retained_dropped: u64,
    /// Sticky identity verdict (M2): every post-ingest verification
    /// passed. Once false, the session's exact counts are void
    /// (coverage consults this; pairing never does).
    pub view_valid: bool,
    /// Pre-arm `LLOSS` per-class totals (M2 baseline: receipts report
    /// abs+delta; the oracle's own GO-baseline still owns the verdict).
    pub loss_baseline: [u64; 5],
    /// Pre-arm `LAGG` per-hook accepted totals (M2 baseline).
    pub agg_baseline: [u64; 16],
    /// Per-program recursion-miss abs+delta (H2 coverage: a wholly
    /// skipped call leaves no edge and no `LLOSS` — only the kernel
    /// miss counter sees it, so any nonzero delta voids exact
    /// counts; receipts report abs+delta per program).
    pub prog_misses: Vec<ProgMissDelta>,
    /// Final per-program miss absolutes (the canary's own
    /// GO-baselines measure from these — the pre-arm join above
    /// brackets the whole session, the oracle owns the verdict).
    pub miss_current: Vec<ProgMisses>,
    /// Transform-lifetime loss counters (T07.6 seam: the
    /// tracker's drops/unknowns/ambiguity join the terminal
    /// accounting — a quiet ledger with nonzero loss is loud).
    pub tfm_stats: TfmStats,
    /// Opaque transform generations assigned this session (T07.6
    /// seam: pointer-free public view — ids, provenance,
    /// retire/ambiguity verdicts, configuration epochs; the
    /// canonical bases stay inside the tracker, never rendered).
    pub generations: Vec<GenerationInfo>,
    /// Registry-enrichment status (T07-09: available snapshot vs
    /// explicit unavailable reason — the report distinguishes
    /// them, capture never refuses on the latter).
    pub enrichment: EnrichmentStatus,
}

/// Terminal-ledger read failure (fail loud: an unreadable counter
/// must never read as zero — coverage would certify blind).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// `LLOSS`/`LAGG` map-counter read failed.
    Counters(MapOpsError),
    /// Per-program recursion-miss read failed.
    Misses(crate::kcrypto_lifecycle::view::ViewError),
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Counters(err) => write!(f, "terminal ledger counters: {err}"),
            Self::Misses(err) => write!(f, "terminal ledger prog misses: {err}"),
        }
    }
}

impl std::error::Error for LedgerError {}

/// Kernel-side session context for the terminal ledger (M2/H2): the
/// pre-arm counter baselines plus the sticky identity verdict. The
/// sensor shell builds it; tests inject it.
#[derive(Debug, Clone)]
pub struct SessionContext {
    /// Pre-arm `LLOSS` per-class totals.
    pub loss_baseline: [u64; 5],
    /// Pre-arm `LAGG` per-hook accepted totals.
    pub agg_baseline: [u64; 16],
    /// Sticky identity verdict at ledger time.
    pub view_valid: bool,
    /// Pre-arm per-program recursion-miss absolutes (H2 baseline).
    pub miss_baseline: Vec<ProgMisses>,
    /// Registry-enrichment status (the shell builds it from the
    /// bring-up snapshot outcome; tests inject it).
    pub enrichment: EnrichmentStatus,
}

/// Pure ingest core: decoder + reducer + completed records (no fds,
/// no syscalls — the unit-testable heart of the drain).
#[derive(Debug)]
pub struct SensorCore {
    decoder: LifecycleDecoder,
    reducer: LifecycleReducer,
    completed: Vec<RequestRecord>,
    edge_hits: [u64; 16],
    ledger_capacity: usize,
    retained_dropped: u64,
    tfm: TransformTracker,
}

impl SensorCore {
    /// New core with bounded decode + reducer tables and a bounded
    /// completed-retention ledger (design C12: every output queue has
    /// a configured bound — round-1 astra-M7). The decode bound is a
    /// pure userspace cap (W8: the kernel holds no pairing state —
    /// invocations live in per-call cookies, not a slot table); the
    /// transform tracker shares the decode-bound scale for its
    /// pending table (in-flight allocations are rarer than
    /// invocations, so the shared bound is generous — one
    /// decode-bound scale for all decode tables). `frontend_off` is
    /// the BTF-resolved `crypto_skcipher.base` offset the arm hands
    /// down (the tracker normalizes frontends with it);
    /// `refcnt_present` is the arm's kernel verdict (the tracker
    /// retires on observed refcount 1 when true, unconditionally
    /// when false — 7.2 dropped the field).
    #[must_use]
    pub fn new(
        decode_capacity: usize,
        reducer_capacity: usize,
        ledger_capacity: usize,
        frontend_off: u32,
        refcnt_present: bool,
    ) -> Self {
        Self {
            decoder: LifecycleDecoder::new(decode_capacity),
            reducer: LifecycleReducer::new(reducer_capacity),
            completed: Vec::new(),
            edge_hits: [0; 16],
            ledger_capacity,
            retained_dropped: 0,
            tfm: TransformTracker::new(decode_capacity, frontend_off, refcnt_present),
        }
    }

    /// The transform-lifetime tracker (T07 generations + loss).
    #[must_use]
    pub fn tfm(&self) -> &TransformTracker {
        &self.tfm
    }

    /// Retain completions up to the ledger bound; past the bound the
    /// records are dropped but COUNTED (explicit loss, never silent
    /// growth — a draining reader via [`Self::take_completed`] never
    /// drops).
    fn retain(&mut self, done: impl IntoIterator<Item = RequestRecord>) {
        for record in done {
            if self.completed.len() < self.ledger_capacity {
                self.completed.push(record);
            } else {
                self.retained_dropped += 1;
            }
        }
    }

    /// Drain retained completions (the live tick's read path);
    /// drained records free retention for new ones.
    pub fn take_completed(&mut self) -> Vec<RequestRecord> {
        std::mem::take(&mut self.completed)
    }

    /// Ingest raw ring records: validate once, tally the per-hook hit,
    /// join to edges, apply to the reducer, append completions to the
    /// ledger. Returns the newly completed record count.
    pub fn ingest_records(&mut self, records: &[Vec<u8>]) -> usize {
        let mut newly = 0;
        for record in records {
            // Magic-routed: transform edges validate, tally their
            // `LAGG_*` hook lane (the equation's consumed side covers
            // transform hooks exactly like op hooks), and join in the
            // tracker (their generations surface in the ledger at
            // T07.6; T07.2 tracks allocs, T07.3 retires destroys).
            // Everything else feeds the op
            // decoder (which refuses non-`LEdge` shapes as twin
            // drift).
            if is_tfm_record(record) {
                let raw = match decode_tfm_record(record) {
                    Ok(raw) => raw,
                    Err(_) => {
                        self.tfm.count_bad_record();
                        continue;
                    }
                };
                self.edge_hits[tfm_slot(raw.site, raw.edge)] += 1;
                self.tfm.join(raw);
                continue;
            }
            let raw = match decode_record(record) {
                Ok(raw) => raw,
                Err(_) => {
                    self.decoder.count_bad_record();
                    continue;
                }
            };
            // T07.3 first-seen, R2 submit-only: the SUBMIT's live
            // entry chase (word + driver) offers the transform to
            // the tracker — returns carry no chase (honest BPF
            // never reads freed request memory at exit), so only
            // submits admit; a return without submit evidence
            // leaves the association unknown (the decoder counts
            // the orphan, never a phantom admission). 0 admits
            // nothing and counts `unlinked_ops` inside; known
            // bases no-op.
            if raw.edge == LEDGE_SUBMIT {
                self.tfm.admit_first_seen(raw.tfm, &raw.drv, raw.truncated);
            }
            let slot = edge_slot(raw.site, raw.edge);
            self.edge_hits[slot] += 1;
            for edge in self.decoder.join(raw) {
                let done = self.reducer.apply(edge);
                newly += done.len();
                self.retain(done);
            }
        }
        newly
    }

    /// Drain pending truthless into retention (stop-the-world; see
    /// reducer `finish`). Returns nothing by design: the take below is
    /// the ONE read path — a finish that both returned and retained
    /// double-surfaced every reconciled record (round-3 async canary).
    /// Transform attempts finalize alongside (T07-06: dangling
    /// destroys mark their still-live bound generation ambiguous —
    /// the ledger's `tfm_stats` carries the whole close account).
    pub fn finish(&mut self, stop_ns: u64) {
        let done = self.reducer.finish(stop_ns);
        self.retain(done);
        self.tfm.finish();
    }

    /// Snapshot the terminal ledger with caller-supplied kernel
    /// counters + current miss absolutes + session context (the
    /// sensor shell reads `LLOSS` + `LAGG`, the current miss
    /// absolutes, and the M2 baseline/verdict; tests inject). The
    /// pre-arm→final miss join computes HERE — the one join site —
    /// and its refusal (backwards, unbaselined, or vanished
    /// counters) fails the ledger: no ledger, no clean verdict.
    pub fn ledger(
        &self,
        kernel_loss: [u64; 5],
        agg_accepted: [u64; 16],
        miss_current: Vec<ProgMisses>,
        ctx: SessionContext,
    ) -> Result<LifecycleLedger, crate::kcrypto_lifecycle::view::ViewError> {
        let prog_misses = join_miss_deltas(&ctx.miss_baseline, &miss_current)?;
        Ok(LifecycleLedger {
            completed: self.completed.clone(),
            edge_hits: self.edge_hits,
            decode: self.decoder.stats(),
            reducer: self.reducer.stats(),
            kernel_loss,
            agg_accepted,
            retained_dropped: self.retained_dropped,
            view_valid: ctx.view_valid,
            loss_baseline: ctx.loss_baseline,
            agg_baseline: ctx.agg_baseline,
            prog_misses,
            miss_current,
            tfm_stats: self.tfm.stats(),
            generations: self.tfm.generations(),
            enrichment: ctx.enrichment,
        })
    }
}

/// One drain's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainOutcome {
    /// Raw records consumed from the ring.
    pub records: usize,
    /// Newly completed request records.
    pub completed: usize,
    /// Stopped on a busy/torn record: more may arrive later.
    pub busy: bool,
}

/// Quiet-drain visit budget per round: 8192 covers a full ring
/// (262144 B / 48 B per frame ≈ 5461 records) plus margin, still
/// bounded — one round plays any close backlog the ring can hold.
pub const QUIET_DRAIN_BUDGET: usize = 8192;

/// Quiet-drain round cap: post-detach arrivals are impossible, so 8
/// rounds (≈43K records) can only exhaust on a corrupt ring — and
/// then the exact backlog, not silence, reaches the ledger.
pub const CLOSE_DRAIN_ROUNDS: usize = 8;

/// Sensor lifecycle state (M1: explicit ADMIT/DRAIN/CLOSED —
/// arm-after-links, disarm-before-detach, never `Vec::clear` drop
/// order). Transitions run one way: [`SensorState::Admit`] →
/// [`SensorState::Draining`] (via [`LifecycleSensor::close_input`])
/// → [`SensorState::Closed`] (via [`LifecycleSensor::drain_quiet`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorState {
    /// Armed and admitting: live ticks drain here.
    Admit,
    /// Disarmed and detached: the closing drain runs here.
    Draining,
    /// Quiet-drained and reported: drains refuse, reads stay open.
    Closed,
}

impl SensorState {
    /// State word for protocol refusals.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admit => "Admit",
            Self::Draining => "Draining",
            Self::Closed => "Closed",
        }
    }
}

/// Attached lifecycle sensor: the single owner (configured maps,
/// programs, links), the single drain (mmap'd ring + consumer
/// position), and the ingest core feeding the terminal ledger.
pub struct LifecycleSensor {
    configured: ConfiguredLifecycle,
    area: RingArea,
    consumer: u64,
    core: SensorCore,
    session: SessionGuard,
    state: SensorState,
    /// Pre-arm identity baseline (M2: every fd pinned before ingest).
    baseline: SensorIdentity,
    /// Sticky identity verdict (M2: once false, never true again —
    /// plain `Relaxed` load/store, cf. the backend's `decoded`).
    view_valid: AtomicBool,
    /// Pre-arm `LLOSS` per-class totals (M2 baseline).
    loss_baseline: [u64; 5],
    /// Pre-arm `LAGG` per-hook accepted totals (M2 baseline).
    agg_baseline: [u64; 16],
    /// Pre-arm per-program recursion-miss absolutes (H2 baseline).
    miss_baseline: Vec<ProgMisses>,
    /// Bounded startup `/proc/crypto` snapshot (T07.5 registry
    /// context — `None` when the read failed; enrichment is
    /// optional, capture never refuses on it).
    registry: Option<ProcCryptoSnapshot>,
    /// Bring-up snapshot failure text (T07-09: `Some` exactly when
    /// `registry` is `None` — the terminal reason capture never
    /// refuses on).
    registry_error: Option<String>,
}

impl std::fmt::Debug for LifecycleSensor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Manual (KCryptoBackend idiom): the mmap'd area holds raw
        // mapping pointers that must never render into diagnostics.
        f.debug_struct("LifecycleSensor")
            .field("links", &self.configured.links.len())
            .field("consumer", &self.consumer)
            .field("completed", &self.core.completed.len())
            .field("session", &self.session)
            .field(
                "registry_entries",
                &self.registry.as_ref().map(|r| r.entries.len()),
            )
            .finish_non_exhaustive()
    }
}

impl LifecycleSensor {
    /// Bring up the sensor: resolve + load + attach every required
    /// site disarmed (see [`load_lifecycle_configured`]), mmap the
    /// ring, then arm (M1: arm-after-links). Fails unless the full
    /// profile attaches AND arms (all-or-nothing: a failed arm drops
    /// the attached-but-disarmed sensor with the error, so a returned
    /// error always means no live sensor).
    pub fn bring_up(
        object_bytes: &[u8],
        token_fd: Option<RawFd>,
    ) -> Result<(Self, Vec<ConfiguredPoint>), ConfiguredError> {
        // Claim the process share first (no cross-profile capture: a
        // live api-returns session refuses this typed — and no second
        // lifecycle holder, H5). Any later failure drops the local
        // hold (a failed bring-up holds nothing).
        let session =
            acquire_kcrypto_session(LifecycleProfile::RequestLifecycle).map_err(|busy| {
                ConfiguredError::SessionBusy {
                    live: busy.live,
                    want: busy.want,
                }
            })?;
        let (configured, points) = load_lifecycle_configured(object_bytes, token_fd)?;
        let area =
            RingArea::map(&configured.loaded.maps.ring, ring_max() as u32).map_err(|err| {
                ConfiguredError::AttachSetup {
                    detail: format!("lring mmap: {err}"),
                }
            })?;
        // M2 pre-arm baseline (identity + counters) BEFORE the M1 arm:
        // a fresh sensor whose fds fail identity never arms, and edges
        // firing while disarmed feed `LLOSS_DISABLED`, so the arm
        // delay costs nothing silent.
        let baseline =
            SensorIdentity::snapshot(&configured.loaded, &configured.links).map_err(|err| {
                ConfiguredError::AttachSetup {
                    detail: format!("sensor identity: {err}"),
                }
            })?;
        let (loss_baseline, agg_baseline) =
            read_kernel_counters(&configured).map_err(ConfiguredError::Configure)?;
        let miss_baseline = snapshot_prog_misses(&configured.loaded).map_err(|err| {
            ConfiguredError::AttachSetup {
                detail: format!("sensor prog misses: {err}"),
            }
        })?;
        let offsets = arm_lifecycle_config(&configured.loaded)?;
        // T07.5 registry context: one bounded `/proc/crypto` read
        // (optional enrichment — a failed read snapshots `None`
        // with the reason kept for the terminal ledger, and
        // capture proceeds; runtime selected metadata never
        // depends on it).
        let (registry, registry_error) =
            match snapshot_proc_crypto(std::path::Path::new("/proc/crypto")) {
                Ok(snap) => (Some(snap), None),
                Err(err) => (None, Some(err.to_string())),
            };
        Ok((
            Self {
                configured,
                area,
                consumer: 0,
                core: SensorCore::new(4096, 4096, 4096, offsets.sk_base, offsets.refcnt_present),
                session,
                state: SensorState::Admit,
                baseline,
                view_valid: AtomicBool::new(true),
                loss_baseline,
                agg_baseline,
                miss_baseline,
                registry,
                registry_error,
            },
            points,
        ))
    }

    /// Current lifecycle state (M1 protocol position).
    #[must_use]
    pub fn sensor_state(&self) -> SensorState {
        self.state
    }

    /// Pre-arm identity baseline (M2 receipts: kernel prog/map/link
    /// ids; the H4 exclusion matches foreign links against these).
    #[must_use]
    pub fn baseline_identity(&self) -> &SensorIdentity {
        &self.baseline
    }

    /// Drain once: walk newly produced records (at most `budget`
    /// visits), ingest them, advance the consumer. Live walk (H1: no
    /// snapshot, no per-drain alloc) + [`SensorCore::ingest_records`];
    /// the VM canary covers this shell.
    pub fn drain_once(&mut self, budget: usize) -> Result<DrainOutcome, DrainError> {
        if self.state == SensorState::Closed {
            return Err(DrainError::StateInvalid {
                expected: "Admit|Draining",
                actual: self.state.as_str(),
            });
        }
        let producer = self.area.producer();
        let consumed = self.area.consume_live(self.consumer, producer, budget);
        let completed = self.core.ingest_records(&consumed.records);
        self.consumer = consumed.consumer;
        self.area.set_consumer(consumed.consumer);
        Ok(DrainOutcome {
            records: consumed.records.len(),
            completed,
            busy: consumed.busy,
        })
    }

    /// Re-verify identity against the pre-arm baseline (M2 "read
    /// after ingest"): while attached the full view (progs + maps +
    /// links) must match; after detach the progs + maps must match
    /// with the link set empty (detached by design — a surviving
    /// link is a leak). A mismatch flips the sticky verdict off
    /// (never back on) and returns the cause. Drivers call this
    /// post-ingest pre-close (full) AND the ledger calls it
    /// post-close (detached) — both reads feed the same sticky bit.
    pub fn verify_identity(&self) -> Result<(), crate::kcrypto_lifecycle::view::ViewError> {
        if !self.view_valid.load(Ordering::Relaxed) {
            // Already void — the sticky bit carries the first cause
            // (re-verifying cannot clear it, so skip the syscalls).
            return Ok(());
        }
        let current = SensorIdentity::snapshot(&self.configured.loaded, &self.configured.links);
        let verified = match current {
            Ok(view) if self.configured.links.is_empty() => view.verify_detached(&self.baseline),
            Ok(view) => view.verify_against(&self.baseline),
            Err(err) => Err(err),
        };
        if verified.is_err() {
            self.view_valid.store(false, Ordering::Relaxed);
        }
        verified
    }

    /// Snapshot the terminal ledger: re-verify identity (post-detach
    /// shape — see [`Self::verify_identity`]) and report the sticky
    /// verdict with the counters + joined per-program miss deltas.
    /// The counter reads still run after a void verdict, and THEY
    /// fail independently on bad fds (an unreadable miss counter
    /// fails the ledger — never a silent zero); the checked
    /// pre-arm→final join refuses backwards, unbaselined, or
    /// vanished counters through the same [`LedgerError::Misses`]
    /// channel.
    pub fn ledger(&self) -> Result<LifecycleLedger, LedgerError> {
        let _ = self.verify_identity();
        let (kernel_loss, agg_accepted) =
            read_kernel_counters(&self.configured).map_err(LedgerError::Counters)?;
        let miss_current =
            snapshot_prog_misses(&self.configured.loaded).map_err(LedgerError::Misses)?;
        // T07-09: the bring-up snapshot outcome reaches the
        // terminal ledger — available inventory vs an explicit
        // unavailable reason (the `None`/`None` arm is unreachable
        // by construction; it reports unreachable-loud, never a
        // fabricated empty inventory).
        let enrichment = match (&self.registry, &self.registry_error) {
            (Some(snap), None) => EnrichmentStatus::Available {
                entries: snap.entries.len(),
                truncated: snap.truncated,
            },
            (None, Some(reason)) => EnrichmentStatus::Unavailable {
                reason: reason.clone(),
            },
            (None, None) => EnrichmentStatus::Unavailable {
                reason: "sensor invariant: snapshot outcome unrecorded".to_owned(),
            },
            (Some(_), Some(_)) => EnrichmentStatus::Unavailable {
                reason: "sensor invariant: snapshot and error both set".to_owned(),
            },
        };
        self.core
            .ledger(
                kernel_loss,
                agg_accepted,
                miss_current,
                SessionContext {
                    loss_baseline: self.loss_baseline,
                    agg_baseline: self.agg_baseline,
                    view_valid: self.view_valid.load(Ordering::Relaxed),
                    miss_baseline: self.miss_baseline.clone(),
                    enrichment,
                },
            )
            .map_err(LedgerError::Misses)
    }

    /// Ring positions `(consumer, producer)` for stage receipts (M2:
    /// arm/drains/disarm ring-position snapshots).
    #[must_use]
    pub fn ring_positions(&self) -> (u64, u64) {
        (self.consumer, self.area.producer())
    }

    /// Drain retained completions (the live tick's read path).
    pub fn take_completed(&mut self) -> Vec<RequestRecord> {
        self.core.take_completed()
    }

    /// The transform-lifetime tracker (T07.6 ledger seam LANDED:
    /// generations + loss surface in [`LifecycleLedger`]; this
    /// accessor stays for qualification drivers and ignored tests
    /// that read live tracker state mid-session).
    #[must_use]
    pub fn tfm(&self) -> &TransformTracker {
        self.core.tfm()
    }

    /// Live attach count: one link per required edge (the session
    /// coverage counts this — links exist only for attached points).
    #[must_use]
    pub fn attached_points(&self) -> usize {
        self.configured.links.len()
    }

    /// Bounded startup `/proc/crypto` snapshot (T07.5 registry
    /// context — current inventory only, never proof of what an
    /// earlier allocation used; `None` when the bring-up read
    /// failed, which never refuses capture).
    #[must_use]
    pub fn registry(&self) -> Option<&ProcCryptoSnapshot> {
        self.registry.as_ref()
    }

    /// Drain pending truthless into retention (stop-the-world): the
    /// live driver's final reconciliation (see reducer `finish`).
    /// Returns nothing — read via [`Self::take_completed`].
    pub fn finish(&mut self, stop_ns: u64) {
        self.core.finish(stop_ns);
    }

    /// Disarm-then-detach, step 1 (M1): prove the disarmed `LCFG`
    /// value FIRST, then drop every attach link (explicit order —
    /// never `Vec::clear` drop order). Idempotent (a second call is a
    /// no-op `Ok`). A failed disarm still detaches — a detached
    /// sensor fires nothing, so the config value is moot — but the
    /// error attests the disarm was never proven. No hook fires after
    /// this returns, so the closing drain converges instead of chasing
    /// arrivals.
    pub fn close_input(&mut self) -> Result<(), ConfiguredError> {
        if self.state != SensorState::Admit {
            return Ok(());
        }
        let disarm = disarm_lifecycle_config(&self.configured.loaded);
        self.configured.links.clear();
        self.state = SensorState::Draining;
        disarm
    }

    /// Detach-then-drain, step 2: bounded quiet loop (at most
    /// [`CLOSE_DRAIN_ROUNDS`] walks of [`QUIET_DRAIN_BUDGET`] visits).
    /// Requires [`SensorState::Draining`] (call [`Self::close_input`]
    /// first — draining an admitting sensor chases arrivals and never
    /// certifies quiet). A round is quiet when it consumes nothing and
    /// sees no busy writer. The verdict carries the exact close backlog
    /// (`producer - consumer` after the last round) to the caller —
    /// the driver feeds it to coverage, so teardown backlog flips
    /// `detailed_events` instead of vanishing with the sensor. Marks
    /// the sensor [`SensorState::Closed`] — reported, never re-drained.
    pub fn drain_quiet(&mut self) -> Result<QuietOutcome, DrainError> {
        if self.state != SensorState::Draining {
            return Err(DrainError::StateInvalid {
                expected: "Draining (call close_input first)",
                actual: self.state.as_str(),
            });
        }
        let mut rounds = 0u64;
        let mut records = 0usize;
        let mut quiet = false;
        for _ in 0..CLOSE_DRAIN_ROUNDS {
            let drained = self.drain_once(QUIET_DRAIN_BUDGET)?;
            rounds += 1;
            records += drained.records;
            if drained.records == 0 && !drained.busy {
                quiet = true;
                break;
            }
        }
        let backlog_bytes = self.area.producer().saturating_sub(self.consumer);
        self.state = SensorState::Closed;
        Ok(QuietOutcome {
            rounds,
            records,
            quiet,
            backlog_bytes,
        })
    }
}

/// One quiet-drain verdict: rounds walked, records consumed, whether
/// a quiet round was reached, and the exact close backlog in ring
/// bytes (zero on a clean close).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuietOutcome {
    /// Walk rounds executed (≤ [`CLOSE_DRAIN_ROUNDS`]).
    pub rounds: u64,
    /// Records consumed across all rounds.
    pub records: usize,
    /// A round consumed nothing with no busy writer.
    pub quiet: bool,
    /// `producer - consumer` after the last round.
    pub backlog_bytes: u64,
}
