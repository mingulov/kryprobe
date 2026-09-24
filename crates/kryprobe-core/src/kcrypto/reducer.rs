// SPDX-License-Identifier: GPL-3.0-or-later
//! Lifecycle reducer: pure bounded edge semantics.
//!
//! Terminal truth comes only from edge dispositions supplied by the
//! qualified adapter; the reducer never infers queue semantics from
//! errno alone. Durations span submit to the edge that carried
//! terminal truth — never invented.

use std::collections::{HashMap, HashSet, VecDeque};

/// How the qualified adapter classifies a function return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnDisposition {
    /// The return value is the final result (synchronous path).
    Terminal,
    /// The request was accepted for async completion; a terminal
    /// callback (or its retained fact) completes it.
    Queued,
    /// The adapter could not classify this return; never completes.
    Unresolved,
}

/// How the qualified adapter classifies a callback invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackDisposition {
    /// Progress notification only; never completes (a -115 callback
    /// stays progress).
    Progress,
    /// The callback carries the final result.
    Terminal,
    /// The adapter could not classify this callback; never completes.
    Unresolved,
}

/// One observed lifecycle edge, in per-source arrival order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    /// Request submitted; opens the id's lifecycle.
    Submit {
        /// Opaque request id.
        id: u64,
        /// Opaque transform id, when observed at submit.
        tfm_id: Option<u64>,
        /// Submit timestamp (ns).
        ts_ns: u64,
    },
    /// Function returned for a submitted id.
    Return {
        /// Opaque request id.
        id: u64,
        /// Return timestamp (ns).
        ts_ns: u64,
        /// Native errno-style status from the adapter.
        status: i32,
        /// Adapter classification; only `Terminal` completes alone.
        disposition: ReturnDisposition,
    },
    /// Callback fired for a submitted id.
    Callback {
        /// Opaque request id.
        id: u64,
        /// Callback timestamp (ns).
        ts_ns: u64,
        /// Native errno-style status from the adapter.
        status: i32,
        /// Adapter classification; only `Terminal` completes.
        disposition: CallbackDisposition,
    },
    /// Adapter-declared phase loss for an id: completes a live id
    /// immediately (retained terminal truth if present, else
    /// [`Terminal::Unknown`]).
    Gap {
        /// Opaque request id.
        id: u64,
        /// Why the phase will never arrive.
        reason: GapReason,
    },
}

/// Why the adapter declares a lifecycle phase will never arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapReason {
    /// An expected phase was never observed and will not arrive.
    MissingPhase,
    /// The id's identity cannot be trusted for joins; the id is
    /// retired and further admission under it refused.
    IdentityAmbiguous,
    /// Evidence was lost between the kernel and the reducer.
    TransportLoss,
    /// The wait for pending phases expired.
    Deadline,
}

/// How a request reached its terminal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    /// Completed synchronously with this status.
    Sync(i32),
    /// Completed by a terminal callback with this status.
    Callback(i32),
    /// Terminal state could not be determined.
    Unknown,
}

/// The completed record for one admitted request id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestRecord {
    /// Opaque request id (never a kernel address).
    pub id: u64,
    /// Opaque transform id, when the submit carried one.
    pub tfm_id: Option<u64>,
    /// How the request completed.
    pub terminal: Terminal,
    /// Submit-to-terminal-edge span; `None` when either endpoint is
    /// missing or the clock ran backwards.
    pub duration_ns: Option<u64>,
}

/// Cumulative lifecycle counters. Every admitted id is accounted:
/// `admitted == emitted + unfinished + live`, where live is the
/// current pending-set size (not a counter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReducerStats {
    /// Submits that opened a lifecycle.
    pub admitted: u64,
    /// Records produced via `apply` or `finish`.
    pub emitted: u64,
    /// Edges for ids never admitted (and never completed).
    pub orphan: u64,
    /// Edges repeating already-known state (tombstoned ids,
    /// duplicate submits, repeat terminals).
    pub duplicate: u64,
    /// `Unresolved`-disposition edges on live ids.
    pub ambiguous: u64,
    /// Fresh submits refused because the live set was full.
    pub admission_failed: u64,
    /// Ids dropped by `finish` without terminal truth.
    pub unfinished: u64,
}

/// One admitted request awaiting terminal reconciliation.
#[derive(Debug)]
struct Pending {
    submit_ts: u64,
    tfm_id: Option<u64>,
    terminal: Option<(Terminal, u64)>,
    return_queued: bool,
}

/// Pure bounded reducer: folds [`Edge`]s into [`RequestRecord`]s.
#[derive(Debug)]
pub struct LifecycleReducer {
    capacity: usize,
    pending: HashMap<u64, Pending>,
    completed: HashSet<u64>,
    tombstone_order: VecDeque<u64>,
    stats: ReducerStats,
}

impl LifecycleReducer {
    /// Creates a reducer admitting at most `capacity` live requests.
    /// Tombstones are bounded by the same capacity (FIFO eviction).
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            pending: HashMap::new(),
            completed: HashSet::new(),
            tombstone_order: VecDeque::new(),
            stats: ReducerStats::default(),
        }
    }

    /// Returns the cumulative counters.
    pub fn stats(&self) -> ReducerStats {
        self.stats
    }

    /// Tombstones a completed id, evicting the oldest tombstone past
    /// capacity. Eviction is explicit, never a silent merge: a
    /// resubmitted evicted id starts a fresh lifecycle with fresh
    /// counters.
    fn tombstone(&mut self, id: u64) {
        if self.completed.insert(id) {
            self.tombstone_order.push_back(id);
            while self.tombstone_order.len() > self.capacity {
                if let Some(old) = self.tombstone_order.pop_front() {
                    self.completed.remove(&old);
                }
            }
        }
    }

    /// Builds the completion record for a drained pending id: retained
    /// terminal truth when present, else [`Terminal::Unknown`] with no
    /// duration. Returns the record and whether terminal truth existed.
    fn reconcile(id: u64, p: &Pending) -> (RequestRecord, bool) {
        match p.terminal {
            Some((terminal, terminal_ts)) => (
                RequestRecord {
                    id,
                    tfm_id: p.tfm_id,
                    terminal,
                    duration_ns: terminal_ts.checked_sub(p.submit_ts),
                },
                true,
            ),
            None => (
                RequestRecord {
                    id,
                    tfm_id: p.tfm_id,
                    terminal: Terminal::Unknown,
                    duration_ns: None,
                },
                false,
            ),
        }
    }

    /// Folds one edge; returns records completed by this edge (usually
    /// zero or one). Duplicate terminals after completion emit nothing.
    pub fn apply(&mut self, edge: Edge) -> Vec<RequestRecord> {
        match edge {
            Edge::Submit { id, tfm_id, ts_ns } => {
                if self.completed.contains(&id) || self.pending.contains_key(&id) {
                    self.stats.duplicate += 1;
                    return Vec::new();
                }
                if self.pending.len() >= self.capacity {
                    self.stats.admission_failed += 1;
                    return Vec::new();
                }
                self.pending.insert(
                    id,
                    Pending {
                        submit_ts: ts_ns,
                        tfm_id,
                        terminal: None,
                        return_queued: false,
                    },
                );
                self.stats.admitted += 1;
                Vec::new()
            }
            Edge::Callback {
                id,
                ts_ns,
                status,
                disposition,
            } => {
                if self.completed.contains(&id) {
                    self.stats.duplicate += 1;
                    return Vec::new();
                }
                let snap = self
                    .pending
                    .get(&id)
                    .map(|p| (p.terminal, p.return_queued, p.submit_ts, p.tfm_id));
                let Some((retained, return_queued, submit_ts, tfm_id)) = snap else {
                    self.stats.orphan += 1;
                    return Vec::new();
                };
                match disposition {
                    CallbackDisposition::Terminal => {
                        if retained.is_some() {
                            self.stats.duplicate += 1;
                            return Vec::new();
                        }
                        if return_queued {
                            self.pending.remove(&id);
                            self.tombstone(id);
                            self.stats.emitted += 1;
                            return vec![RequestRecord {
                                id,
                                tfm_id,
                                terminal: Terminal::Callback(status),
                                duration_ns: ts_ns.checked_sub(submit_ts),
                            }];
                        }
                        if let Some(p) = self.pending.get_mut(&id) {
                            p.terminal = Some((Terminal::Callback(status), ts_ns));
                        }
                        Vec::new()
                    }
                    // Routine progress on a live id: observed, uncounted.
                    CallbackDisposition::Progress => Vec::new(),
                    CallbackDisposition::Unresolved => {
                        self.stats.ambiguous += 1;
                        Vec::new()
                    }
                }
            }
            Edge::Return {
                id,
                ts_ns,
                status,
                disposition,
            } => {
                if self.completed.contains(&id) {
                    self.stats.duplicate += 1;
                    return Vec::new();
                }
                if !self.pending.contains_key(&id) {
                    self.stats.orphan += 1;
                    return Vec::new();
                }
                if disposition == ReturnDisposition::Unresolved {
                    self.stats.ambiguous += 1;
                    return Vec::new();
                }
                // A sync return contradicting retained callback truth: the
                // first terminal wins and the conflict is counted.
                if disposition == ReturnDisposition::Terminal {
                    let conflict = match self.pending.get(&id) {
                        Some(p) => p.terminal.map(|(t, tts)| (t, tts, p.tfm_id, p.submit_ts)),
                        None => None,
                    };
                    if let Some((terminal, terminal_ts, tfm_id, submit_ts)) = conflict {
                        self.pending.remove(&id);
                        self.tombstone(id);
                        self.stats.emitted += 1;
                        self.stats.ambiguous += 1;
                        return vec![RequestRecord {
                            id,
                            tfm_id,
                            terminal,
                            duration_ns: terminal_ts.checked_sub(submit_ts),
                        }];
                    }
                }
                let ready = match self.pending.get(&id) {
                    Some(p) => match disposition {
                        ReturnDisposition::Terminal => Some((
                            p.tfm_id,
                            Terminal::Sync(status),
                            ts_ns.checked_sub(p.submit_ts),
                        )),
                        ReturnDisposition::Queued => p
                            .terminal
                            .map(|(t, tts)| (p.tfm_id, t, tts.checked_sub(p.submit_ts))),
                        ReturnDisposition::Unresolved => None,
                    },
                    None => None,
                };
                // Non-emitting returns retain the pending record: a later
                // terminal edge may still complete the request. Reaching
                // `None` here means a Queued return with no terminal yet
                // (unknown ids and Unresolved returns exit above), so mark
                // the return observed for the joining callback.
                match ready {
                    Some((tfm_id, terminal, duration_ns)) => {
                        self.pending.remove(&id);
                        self.tombstone(id);
                        self.stats.emitted += 1;
                        vec![RequestRecord {
                            id,
                            tfm_id,
                            terminal,
                            duration_ns,
                        }]
                    }
                    None => {
                        if let Some(p) = self.pending.get_mut(&id) {
                            p.return_queued = true;
                        }
                        Vec::new()
                    }
                }
            }
            Edge::Gap { id, reason: _ } => {
                if self.completed.contains(&id) {
                    self.stats.duplicate += 1;
                    return Vec::new();
                }
                let Some(p) = self.pending.remove(&id) else {
                    self.stats.orphan += 1;
                    return Vec::new();
                };
                self.tombstone(id);
                self.stats.emitted += 1;
                let (record, _) = Self::reconcile(id, &p);
                vec![record]
            }
        }
    }

    /// Drains every pending id in ascending id order: ids with
    /// retained terminal truth emit it; the rest emit
    /// [`Terminal::Unknown`] with no duration and count as
    /// [`ReducerStats::unfinished`]. `stop_ns` labels when the drain
    /// happened; reconciliation depends only on observed edges.
    /// Drained ids are tombstoned. A second call emits nothing.
    pub fn finish(&mut self, _stop_ns: u64) -> Vec<RequestRecord> {
        let mut ids: Vec<u64> = self.pending.keys().copied().collect();
        ids.sort_unstable();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(p) = self.pending.remove(&id) else {
                continue;
            };
            let (record, had_truth) = Self::reconcile(id, &p);
            if !had_truth {
                self.stats.unfinished += 1;
            }
            self.tombstone(id);
            self.stats.emitted += 1;
            out.push(record);
        }
        out
    }
}
