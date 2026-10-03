// SPDX-License-Identifier: GPL-3.0-or-later
//! Aggregate session ownership and the checked, non-atomic terminal sample.

use super::*;
use crate::drain::{DrainStats, DrainThread};
use crate::kcrypto_snapshot::{
    AggOccupancy, CtxTerminal, SnapshotRows, session_drain, snapshot_occupancy,
    snapshot_rows_with_drain, terminal_rows,
};

/// One checked terminal sample. Closing links and joining the host drain do
/// not prove that all kernel writers have completed; every map read here is
/// still non-atomic with respect to those writers.
#[derive(Debug, Clone)]
pub struct AggregateTerminalSample {
    /// Final aggregate/totals rows and the joined drain's identity tail.
    pub snapshot: SnapshotRows,
    /// Fresh who rows, with cold stack/error/parameter joins.
    pub who: Vec<WhoSnapshot>,
    /// Measured attribution insertion-loss indicator.
    pub who_drops: u64,
    /// Measured pre-KTOT drop-site counters.
    pub drops: [u64; 8],
    /// Joined transport statistics, including bounded-sweep residue.
    pub drain: DrainStats,
    /// Monotonic lower bound recorded before the first possible attach.
    pub started_ns: u64,
    /// ctx-v1 writer-fence outcome: `Quiescent` (with the completion
    /// bound) proves no admitted writer remained when the terminal
    /// reads ran; `Pending` means the drain deadline exhausted and
    /// the snapshot stays a non-atomic sample.
    pub fence: crate::kcrypto_fence::CloseOutcome,
}

impl AggregateTerminalSample {
    /// Reject contradictory clocks rather than clamping them into the interval.
    pub fn validate_interval(&self) -> Result<(), BackendError> {
        let end = self.snapshot.monotonic_ns;
        if end < self.started_ns {
            return Err(protocol(
                "kcrypto_terminal_interval",
                "end precedes attach bound",
            ));
        }
        let stamps = |first: u64, last: u64| {
            if (first != 0 && (first < self.started_ns || first > end))
                || (last != 0 && (last < self.started_ns || last > end))
                || (first != 0 && last != 0 && first > last)
            {
                Err(protocol(
                    "kcrypto_terminal_interval",
                    "nonzero row stamp contradicts interval",
                ))
            } else {
                Ok(())
            }
        };
        for row in &self.snapshot.rows {
            match parse_snapshot_row(row.as_bytes())? {
                ParsedRow::Agg { vagg, .. } => stamps(vagg.first_ns, vagg.last_ns)?,
                _ => return Err(protocol("kcrypto_finalize_row_kind", "expected aggregate")),
            }
        }
        if let Some(row) = &self.snapshot.totals {
            match parse_snapshot_row(row.as_bytes())? {
                ParsedRow::Totals { vagg } => stamps(vagg.first_ns, vagg.last_ns)?,
                _ => return Err(protocol("kcrypto_finalize_row_kind", "expected totals")),
            }
        }
        for row in &self.snapshot.idents {
            match parse_snapshot_row(row.as_bytes())? {
                ParsedRow::Ident { kctl } => stamps(kctl.val2, kctl.val2)?,
                _ => return Err(protocol("kcrypto_finalize_row_kind", "expected identity")),
            }
        }
        for who in &self.who {
            stamps(who.val.first_ns, who.val.last_ns)?;
        }
        Ok(())
    }
}

pub(super) enum SessionPhase {
    Active,
    Sampled(IntegritySummary),
    Finalized(BackendSummary),
    Failed(BackendError),
}

pub(super) struct ConfiguredSession {
    pub(super) generation: PlanGeneration,
    pub(super) sensor: ConfiguredKcrypto,
    pub(super) started_ns: u64,
    pub(super) attached_points: usize,
    pub(super) drain: Option<DrainThread>,
    pub(super) drain_stats: Option<DrainStats>,
    pub(super) fence_outcome: Option<crate::kcrypto_fence::CloseOutcome>,
    pub(super) who_cache: WhoCache,
    pub(super) phase: SessionPhase,
}

impl ConfiguredSession {
    pub(super) fn new(
        generation: PlanGeneration,
        sensor: ConfiguredKcrypto,
        started_ns: u64,
    ) -> Self {
        let attached_points = sensor.links.len();
        Self {
            generation,
            sensor,
            started_ns,
            attached_points,
            drain: None,
            drain_stats: None,
            fence_outcome: None,
            who_cache: WhoCache::new(),
            phase: SessionPhase::Active,
        }
    }

    fn active(&self) -> Result<(), BackendError> {
        match &self.phase {
            SessionPhase::Active => Ok(()),
            _ => Err(protocol(
                "kcrypto_session_closed",
                "session no longer admits reads",
            )),
        }
    }
}

pub(super) fn protocol(reason: &'static str, detail: &str) -> BackendError {
    BackendError::Internal(InternalError::with_detail(reason, detail))
}

fn configured(
    state: &mut Option<ConfiguredSession>,
    generation: PlanGeneration,
) -> Result<&mut ConfiguredSession, BackendError> {
    let state = state
        .as_mut()
        .ok_or_else(|| protocol("kcrypto_sensor_unconfigured", "configure first"))?;
    if state.generation != generation {
        return Err(protocol(
            "kcrypto_session_generation",
            "foreign generation refused",
        ));
    }
    Ok(state)
}

impl KCryptoBackend {
    /// Open this generation's one session drain. No link or sensor handle is
    /// duplicated; all map access remains under the backend mutex.
    pub fn open_session(&self, generation: PlanGeneration) -> Result<usize, BackendError> {
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let state = configured(&mut guard, generation)?;
        state.active()?;
        if state.drain.is_some() {
            return Err(protocol(
                "kcrypto_drain_already_open",
                "one collector per session",
            ));
        }
        let drain = session_drain(&state.sensor)
            .map_err(|err| protocol("kcrypto_session_drain", &err.to_string()));
        if let Err(err) = &drain {
            state.phase = SessionPhase::Failed(err.clone());
        }
        state.drain = Some(drain?);
        Ok(state.attached_points)
    }

    /// Read a running tick through the owned drain.
    pub fn session_tick(
        &self,
        generation: PlanGeneration,
        barrier: u64,
    ) -> Result<SnapshotRows, BackendError> {
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let state = configured(&mut guard, generation)?;
        state.active()?;
        let drain = state
            .drain
            .as_ref()
            .ok_or_else(|| protocol("kcrypto_drain_missing", "open session first"))?;
        let result = snapshot_rows_with_drain(&state.sensor, drain, barrier)
            .map_err(|err| protocol("kcrypto_session_tick", &err.to_string()));
        if let Err(err) = &result {
            state.phase = SessionPhase::Failed(err.clone());
        }
        result
    }

    /// Running who snapshots may reuse unchanged joins. Terminal reads below
    /// deliberately start cold, including joins whose value did not advance.
    pub fn session_who(
        &self,
        generation: PlanGeneration,
    ) -> Result<(Vec<WhoSnapshot>, u64), BackendError> {
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let state = configured(&mut guard, generation)?;
        state.active()?;
        let result = snapshot_who_cached(&state.sensor, &mut state.who_cache)
            .map_err(|err| protocol("kcrypto_session_who", &err.to_string()));
        if let Err(err) = &result {
            state.phase = SessionPhase::Failed(err.clone());
        }
        result
    }

    /// Detach links, then close the kernel fence (F1 order,
    /// structural — the ONLY fence path; `finish_session` never calls
    /// `close_kernel_fence` directly). Detaching FIRST stops new BPF
    /// invocations at the source (fast quiescence under load + a
    /// crisp session bound: nothing executes past detach); the fence
    /// then refuses laggards (`CLOSED`) and drain-waits (polls +
    /// visibility grace/rescan). The old order (fence-then-detach
    /// with a single all-zero poll) issued the receipt while an
    /// admitted writer's increment could still be invisible to the
    /// closer — a torn terminal read. Map faults fail loud; deadline
    /// exhaustion yields `Pending`, never a receipt.
    fn detach_and_close_fence(
        state: &mut ConfiguredSession,
    ) -> Result<crate::kcrypto_fence::CloseOutcome, BackendError> {
        state.sensor.links.clear();
        crate::kcrypto_fence::close_kernel_fence(&state.sensor.loaded.maps)
            .map_err(|err| protocol("kcrypto_fence_close", &err.to_string()))
    }

    /// Close owned links once, join and check the drain, then read one terminal
    /// non-atomic sample. Any failure makes finalization sticky-refused.
    pub fn finish_session(
        &self,
        generation: PlanGeneration,
    ) -> Result<AggregateTerminalSample, BackendError> {
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let state = configured(&mut guard, generation)?;
        state.active()?;
        // ctx-v1 fence close (ADR-0009, F1 order): detach FIRST, then
        // refuse + drain — a `Quiescent` receipt proves the terminal
        // reads below saw no admitted writer (nothing can start past
        // detach+CLOSED; the grace+rescan closes the
        // increment-visibility race). A `Pending` close keeps the
        // sample a non-atomic sample (never exact).
        let fence = Self::detach_and_close_fence(state)?;
        // F-01: the receipt gates the terminal ctx read below — a
        // `Pending` close must omit the line, never print a sample as
        // terminal. Recorded before the drain stop so it survives a
        // later drain failure (the fence fact stays factual).
        state.fence_outcome = Some(fence);
        let result = (|| {
            let drain = state
                .drain
                .take()
                .ok_or_else(|| protocol("kcrypto_drain_missing", "no checked collector"))?;
            let (stats, tail) = drain.stop_and_drain();
            let stats = stats.map_err(|err| {
                protocol(
                    "kcrypto_drain_failed",
                    &format!("{err}; forwarded tail events: {}", tail.len()),
                )
            })?;
            state.drain_stats = Some(stats);
            let sample = (|| {
                let mut snapshot = terminal_rows(&state.sensor, tail)
                    .map_err(|err| protocol("kcrypto_terminal_maps", &err.to_string()))?;
                let (who, who_drops) = snapshot_who(&state.sensor)
                    .map_err(|err| protocol("kcrypto_terminal_who", &err.to_string()))?;
                let drops = snapshot_drops(&state.sensor)
                    .map_err(|err| protocol("kcrypto_terminal_drops", &err.to_string()))?;
                snapshot.monotonic_ns = crate::host::monotonic_ns()
                    .map_err(|err| protocol("kcrypto_terminal_clock", &err.to_string()))?;
                let sample = AggregateTerminalSample {
                    snapshot,
                    who,
                    who_drops,
                    drops,
                    drain: stats,
                    started_ns: state.started_ns,
                    fence,
                };
                sample.validate_interval()?;
                let integrity = integrity_for_snapshot(
                    &sample.snapshot,
                    sample.snapshot.drops,
                    sample.who_drops,
                )?;
                Ok((sample, integrity))
            })();
            sample.map_err(|err: BackendError| {
                protocol(
                    "kcrypto_terminal_sample",
                    &format!("{err}; known drain statistics: {stats:?}"),
                )
            })
        })();
        match result {
            Ok((sample, integrity)) => {
                state.phase = SessionPhase::Sampled(integrity);
                Ok(sample)
            }
            Err(err) => {
                state.phase = SessionPhase::Failed(err.clone());
                Err(err)
            }
        }
    }

    /// Error-path cleanup, valid immediately after configure (before drain
    /// creation). Repeated cleanup is harmless; it never samples or finalizes.
    pub fn abort_session(
        &self,
        generation: PlanGeneration,
    ) -> Result<Option<DrainStats>, BackendError> {
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let state = configured(&mut guard, generation)?;
        state.sensor.links.clear();
        let result = match state.drain.take() {
            Some(drain) => {
                let (stats, tail) = drain.stop_and_drain();
                stats
                    .map(|stats| {
                        state.drain_stats = Some(stats);
                    })
                    .map_err(|err| {
                        protocol(
                            "kcrypto_cleanup_drain",
                            &format!("{err}; forwarded tail events: {}", tail.len()),
                        )
                    })
            }
            None => Ok(()),
        };
        if !matches!(state.phase, SessionPhase::Failed(_)) {
            state.phase = SessionPhase::Failed(result.clone().err().unwrap_or_else(|| {
                protocol("kcrypto_session_aborted", "capture did not complete")
            }));
        }
        result.map(|()| state.drain_stats.take())
    }

    /// Best-effort occupancy after link close; metadata is retained, and no
    /// occupied map count is a completeness or quiescence assertion.
    pub fn session_occupancy(
        &self,
        generation: PlanGeneration,
    ) -> Result<AggOccupancy, BackendError> {
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        Ok(snapshot_occupancy(
            &configured(&mut guard, generation)?.sensor,
        ))
    }

    /// Terminal ctx-v1 attribution account from one post-finish read
    /// (M1 early gate): links are closed and the fence is shut, so the
    /// maps are frozen and the walk is a consistent terminal read. The
    /// walk itself is fail-soft per field (see [`CtxTerminal`]).
    /// Fail-closed on the fence receipt (F-01): `Pending` (or no
    /// fence attempt yet) refuses here, and the caller omits the
    /// line — an unproven snapshot never renders as terminal.
    pub fn session_ctx_terminal(
        &self,
        generation: PlanGeneration,
    ) -> Result<CtxTerminal, BackendError> {
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let state = configured(&mut guard, generation)?;
        match state.fence_outcome {
            Some(outcome) if !outcome.is_pending() => Ok(snapshot_ctx_terminal(&state.sensor)),
            Some(_) => Err(protocol(
                "kcrypto_ctx_pending_fence",
                "fence close pending: terminal ctx unproven",
            )),
            None => Err(protocol(
                "kcrypto_ctx_unfenced",
                "terminal ctx read before fence close",
            )),
        }
    }
}
