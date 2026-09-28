// SPDX-License-Identifier: GPL-3.0-or-later
//! Lifecycle reducer: pure bounded edge semantics.
//!
//! Terminal truth comes only from edge dispositions supplied by the
//! qualified adapter; the reducer never infers queue semantics from
//! errno alone. Durations span submit to the edge that carried
//! terminal truth — never invented.

use std::collections::{HashMap, VecDeque};

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

/// Crypto family behind a submitted operation (P3 submit metadata).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleFamily {
    /// `crypto_skcipher_*` sites.
    Skcipher,
    /// `crypto_aead_*` sites (P5: its own family under wire v7,
    /// never a relabeled skcipher — AEAD byte populations differ).
    Aead,
}

/// AEAD submit extension (P5 internal metadata contract v2): the two
/// entry-observed AEAD scalars. Present (`Some`) exactly on AEAD
/// submits; skcipher submits carry `None` (no AEAD lengths ride a
/// skcipher record — populations stay labeled). Each scalar is
/// independently unknown-capable (`None` when its entry chase was
/// unreadable — unknown, never 0-as-data; a valid zero stays
/// `Some(0)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadMeta {
    /// Associated-data length (`aead_request.assoclen` at entry).
    pub assoclen: Option<u32>,
    /// Tag width (submit-chased `crypto_aead.authsize` — the width
    /// the op ran under, like `cryptlen`: current selected state,
    /// not joined history).
    pub authsize: Option<u32>,
}

/// Operation direction behind a submitted op (P3 submit metadata).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpDirection {
    /// `crypto_skcipher_encrypt` site.
    Encrypt,
    /// `crypto_skcipher_decrypt` site.
    Decrypt,
}

/// Entry-side scalar metadata pinned at submit (P3 internal metadata
/// contract v1): every field is observed at the submit edge (or
/// explicitly unknown), never chased at return, never inferred from
/// timing. Internal-only: the report boundary (P6) versions any
/// public emission; until then these fields ride the reducer as
/// opaque facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestMeta {
    /// Crypto family behind the op (wire-pinned per site program).
    pub family: LifecycleFamily,
    /// Operation direction (wire-pinned, echoes the site).
    pub direction: OpDirection,
    /// API input length (`skcipher_request.cryptlen` at entry;
    /// `None` when the entry chase was unreadable — unknown, never 0-as-data).
    pub cryptlen: Option<u32>,
    /// Request flags (`crypto_async_request.flags` at entry;
    /// `None` when unreadable — a valid zero stays `Some(0)`).
    pub req_flags: Option<u32>,
    /// Configuration epoch of the bound generation AT SUBMIT (the
    /// keying era the op ran under — later rekeys never rewrite it);
    /// `None` when the submit bound no generation.
    pub epoch: Option<u64>,
    /// AEAD submit extension (P5 contract v2): `Some` exactly when
    /// `family` is [`LifecycleFamily::Aead`].
    pub aead: Option<AeadMeta>,
}

/// One observed lifecycle edge, in per-source arrival order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    /// Request submitted; opens the id's lifecycle. Submit-first
    /// delivery is an adapter prerequisite: any edge for an id
    /// arriving before its submit is a counted orphan, never joined
    /// retroactively.
    Submit {
        /// Opaque request id.
        id: u64,
        /// Opaque transform id, when observed at submit.
        tfm_id: Option<u64>,
        /// Submit timestamp (ns).
        ts_ns: u64,
        /// Entry-side scalar metadata pinned at submit.
        meta: RequestMeta,
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
    /// [`Terminal::Unknown`]; [`GapReason::IdentityAmbiguous`]
    /// always emits `Unknown`, invalidating even retained truth).
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
    /// The id's identity cannot be trusted for joins. Before
    /// emission, the completion emits [`Terminal::Unknown`] even
    /// when terminal truth was retained, and further admission
    /// under the id is refused while its tombstone is retained.
    /// After emission, the gap flags the tombstone instead (counted
    /// ambiguous, queryable via
    /// [`LifecycleReducer::is_invalidated`]) without retracting the
    /// record. After tombstone eviction the id may be explicitly
    /// re-admitted (bounded memory cannot refuse forever);
    /// cross-lifetime safety then requires lifetime-unique ids
    /// (T08 prerequisite).
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
    /// Entry-side scalar metadata pinned at submit (P3 internal
    /// contract — carried on grounded AND truthless records alike:
    /// submit-observed fact, not terminal truth; public emission
    /// waits for the P6 versioned schema).
    pub meta: RequestMeta,
}

impl RequestRecord {
    /// Evidence validity: true exactly when the record is grounded in
    /// observed terminal truth (`Sync`/`Callback`). `Unknown` records
    /// carry explicit absence-of-truth, never a trusted result.
    pub fn evidence_valid(&self) -> bool {
        self.terminal != Terminal::Unknown
    }
}

/// Cumulative lifecycle counters. Every admitted id is accounted:
/// `admitted == emitted + live`, where live is the current
/// pending-set size (not a counter). `unfinished` is the subset of
/// `emitted` drained truthless by `finish`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReducerStats {
    /// Submits that opened a lifecycle.
    pub admitted: u64,
    /// Records produced via `apply` or `finish`.
    pub emitted: u64,
    /// Edges for ids absent from both the live set and retained
    /// tombstones: never-admitted ids, or admitted ids whose
    /// tombstone was evicted (bounded history cannot tell them
    /// apart).
    pub orphan: u64,
    /// Edges repeating already-known state (tombstoned ids,
    /// duplicate submits, repeat terminals).
    pub duplicate: u64,
    /// Conflicting or unclassifiable evidence: `Unresolved`
    /// dispositions, terminals contradicting the first truth, and
    /// identity-invalidated completions.
    pub ambiguous: u64,
    /// Fresh submits refused because the live set was full.
    pub admission_failed: u64,
    /// Emitted records drained truthless by `finish` (subset of
    /// `emitted`, never double-counted against `admitted`).
    pub unfinished: u64,
}

/// One admitted request awaiting terminal reconciliation.
#[derive(Debug)]
struct Pending {
    submit_ts: u64,
    tfm_id: Option<u64>,
    meta: RequestMeta,
    terminal: Option<(Terminal, u64)>,
    return_queued: bool,
}

/// A completed id's retained truth: the emitted terminal plus whether
/// identity ambiguity invalidated it — at completion (live
/// identity-ambiguity gap) or after (later gap). Invalidation cannot
/// retract the emitted record; consumers check
/// [`LifecycleReducer::is_invalidated`].
#[derive(Debug, Clone, Copy)]
struct Tombstone {
    terminal: Terminal,
    invalidated: bool,
}

/// Pure bounded reducer: folds [`Edge`]s into [`RequestRecord`]s.
#[derive(Debug)]
pub struct LifecycleReducer {
    capacity: usize,
    pending: HashMap<u64, Pending>,
    completed: HashMap<u64, Tombstone>,
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
            completed: HashMap::new(),
            tombstone_order: VecDeque::new(),
            stats: ReducerStats::default(),
        }
    }

    /// Returns the cumulative counters.
    pub fn stats(&self) -> ReducerStats {
        self.stats
    }

    /// Live requests awaiting completion (the reducer half of
    /// stop-phase in-flight — the P7-N5 bounded drain exits early
    /// when this AND the decoder's outstanding set are both empty).
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Whether a completed id was invalidated by identity
    /// ambiguity — at completion (live gap) or after (later gap).
    /// False for live, never-admitted, and evicted ids: eviction
    /// drops the invalidation fact with the tombstone, so
    /// cross-lifetime invalidation tracking requires
    /// lifetime-unique ids (T08 prerequisite).
    pub fn is_invalidated(&self, id: u64) -> bool {
        self.completed
            .get(&id)
            .is_some_and(|stone| stone.invalidated)
    }

    /// Tombstones a completed id with the emitted terminal truth,
    /// evicting the oldest tombstone past capacity. Eviction is
    /// explicit, never a silent merge: a resubmitted evicted id
    /// starts a fresh lifecycle with fresh counters. The retained
    /// truth lets late terminals be compared: repeats are
    /// duplicates, contradictions are ambiguous. `invalidated`
    /// starts true only for completions that are themselves
    /// invalidations (live identity-ambiguity gaps); otherwise
    /// only a later identity-ambiguity gap flags the tombstone.
    fn tombstone(&mut self, id: u64, terminal: Terminal, invalidated: bool) {
        let stone = Tombstone {
            terminal,
            invalidated,
        };
        if self.completed.insert(id, stone).is_none() {
            self.tombstone_order.push_back(id);
            while self.tombstone_order.len() > self.capacity {
                if let Some(old) = self.tombstone_order.pop_front() {
                    self.completed.remove(&old);
                }
            }
        }
    }

    /// Diagnoses a terminal edge against the emitted truth under a
    /// tombstoned id: a repeat is a duplicate; a contradiction is
    /// ambiguous; anything after an `Unknown` completion is a
    /// suppressed duplicate (`Unknown` claims no truth to
    /// contradict).
    fn diagnose_tombstoned(&mut self, emitted: Terminal, candidate: Terminal) {
        match emitted {
            Terminal::Unknown => self.stats.duplicate += 1,
            t if t == candidate => self.stats.duplicate += 1,
            _ => self.stats.ambiguous += 1,
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
                    meta: p.meta,
                },
                true,
            ),
            None => (
                RequestRecord {
                    id,
                    tfm_id: p.tfm_id,
                    terminal: Terminal::Unknown,
                    duration_ns: None,
                    meta: p.meta,
                },
                false,
            ),
        }
    }

    /// Folds one edge; returns records completed by this edge (usually
    /// zero or one). Duplicate terminals after completion emit nothing.
    pub fn apply(&mut self, edge: Edge) -> Vec<RequestRecord> {
        match edge {
            Edge::Submit {
                id,
                tfm_id,
                ts_ns,
                meta,
            } => {
                if self.completed.contains_key(&id) || self.pending.contains_key(&id) {
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
                        meta,
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
                if let Some(stone) = self.completed.get(&id).copied() {
                    if disposition == CallbackDisposition::Terminal {
                        self.diagnose_tombstoned(stone.terminal, Terminal::Callback(status));
                    } else if disposition == CallbackDisposition::Unresolved {
                        // Unclassifiable evidence stays loud after
                        // completion, exactly as on a live id.
                        self.stats.ambiguous += 1;
                    } else {
                        self.stats.duplicate += 1;
                    }
                    return Vec::new();
                }
                let snap = self
                    .pending
                    .get(&id)
                    .map(|p| (p.terminal, p.return_queued, p.submit_ts, p.tfm_id, p.meta));
                let Some((retained, return_queued, submit_ts, tfm_id, meta)) = snap else {
                    self.stats.orphan += 1;
                    return Vec::new();
                };
                match disposition {
                    CallbackDisposition::Progress if retained.is_some() => {
                        // Progress after terminal truth is known is
                        // late traffic: diagnosed exactly like
                        // post-completion progress, so anomaly
                        // accounting does not depend on whether the
                        // joining return has arrived yet.
                        self.stats.duplicate += 1;
                        Vec::new()
                    }
                    CallbackDisposition::Terminal => {
                        // A second terminal callback confirms or
                        // contradicts the retained truth; the first
                        // still wins either way.
                        if let Some((first, _)) = retained {
                            if first == Terminal::Callback(status) {
                                self.stats.duplicate += 1;
                            } else {
                                self.stats.ambiguous += 1;
                            }
                            return Vec::new();
                        }
                        if return_queued {
                            self.pending.remove(&id);
                            self.tombstone(id, Terminal::Callback(status), false);
                            self.stats.emitted += 1;
                            return vec![RequestRecord {
                                id,
                                tfm_id,
                                terminal: Terminal::Callback(status),
                                duration_ns: ts_ns.checked_sub(submit_ts),
                                meta,
                            }];
                        }
                        if let Some(p) = self.pending.get_mut(&id) {
                            p.terminal = Some((Terminal::Callback(status), ts_ns));
                        }
                        Vec::new()
                    }
                    // Routine progress before terminal truth is known:
                    // observed, uncounted.
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
                if let Some(stone) = self.completed.get(&id).copied() {
                    if disposition == ReturnDisposition::Terminal {
                        self.diagnose_tombstoned(stone.terminal, Terminal::Sync(status));
                    } else if disposition == ReturnDisposition::Queued
                        && matches!(stone.terminal, Terminal::Sync(_))
                    {
                        // A Queued classification after synchronous
                        // completion contradicts the emitted truth.
                        self.stats.ambiguous += 1;
                    } else if disposition == ReturnDisposition::Unresolved {
                        // Unclassifiable evidence stays loud after
                        // completion, exactly as on a live id.
                        self.stats.ambiguous += 1;
                    } else {
                        self.stats.duplicate += 1;
                    }
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
                        Some(p) => p
                            .terminal
                            .map(|(t, tts)| (t, tts, p.tfm_id, p.submit_ts, p.meta)),
                        None => None,
                    };
                    if let Some((terminal, terminal_ts, tfm_id, submit_ts, meta)) = conflict {
                        self.pending.remove(&id);
                        self.tombstone(id, terminal, false);
                        self.stats.emitted += 1;
                        self.stats.ambiguous += 1;
                        return vec![RequestRecord {
                            id,
                            tfm_id,
                            terminal,
                            duration_ns: terminal_ts.checked_sub(submit_ts),
                            meta,
                        }];
                    }
                }
                let ready = match self.pending.get(&id) {
                    Some(p) => match disposition {
                        ReturnDisposition::Terminal => Some((
                            p.tfm_id,
                            Terminal::Sync(status),
                            ts_ns.checked_sub(p.submit_ts),
                            p.return_queued,
                            p.meta,
                        )),
                        ReturnDisposition::Queued => p.terminal.map(|(t, tts)| {
                            (p.tfm_id, t, tts.checked_sub(p.submit_ts), false, p.meta)
                        }),
                        ReturnDisposition::Unresolved => None,
                    },
                    None => None,
                };
                // Non-emitting returns retain the pending record: a later
                // terminal edge may still complete the request. Reaching
                // `None` here means a Queued return with no terminal yet
                // (unknown ids and Unresolved returns exit above): the
                // first marks the return observed for the joining
                // callback, a repeat is a duplicate.
                match ready {
                    Some((tfm_id, terminal, duration_ns, queued_before, meta)) => {
                        self.pending.remove(&id);
                        self.tombstone(id, terminal, false);
                        self.stats.emitted += 1;
                        // A terminal return after an observed Queued
                        // return completes but contradicts the earlier
                        // classification.
                        if queued_before {
                            self.stats.ambiguous += 1;
                        }
                        vec![RequestRecord {
                            id,
                            tfm_id,
                            terminal,
                            duration_ns,
                            meta,
                        }]
                    }
                    None => {
                        if let Some(p) = self.pending.get_mut(&id) {
                            if p.return_queued {
                                self.stats.duplicate += 1;
                            } else {
                                p.return_queued = true;
                            }
                        }
                        Vec::new()
                    }
                }
            }
            Edge::Gap { id, reason } => {
                if self.completed.contains_key(&id) {
                    // Identity ambiguity discovered after emission
                    // cannot retract the record, but it must be loud
                    // and queryable: the first late invalidation
                    // counts ambiguous and flags the tombstone (see
                    // `is_invalidated`); repeats are duplicates.
                    if reason == GapReason::IdentityAmbiguous {
                        let fresh = match self.completed.get_mut(&id) {
                            Some(stone) if !stone.invalidated => {
                                stone.invalidated = true;
                                true
                            }
                            _ => false,
                        };
                        if fresh {
                            self.stats.ambiguous += 1;
                        } else {
                            self.stats.duplicate += 1;
                        }
                    } else {
                        self.stats.duplicate += 1;
                    }
                    return Vec::new();
                }
                let Some(p) = self.pending.remove(&id) else {
                    self.stats.orphan += 1;
                    return Vec::new();
                };
                // An untrusted identity invalidates even retained terminal
                // truth: emit Unknown, never a trusted-looking result.
                if reason == GapReason::IdentityAmbiguous {
                    self.tombstone(id, Terminal::Unknown, true);
                    self.stats.emitted += 1;
                    self.stats.ambiguous += 1;
                    return vec![RequestRecord {
                        id,
                        tfm_id: p.tfm_id,
                        terminal: Terminal::Unknown,
                        duration_ns: None,
                        meta: p.meta,
                    }];
                }
                let (record, _) = Self::reconcile(id, &p);
                self.tombstone(id, record.terminal, false);
                self.stats.emitted += 1;
                vec![record]
            }
        }
    }

    /// Expires pending ids older than the bound (P7/T12 injection
    /// seam): every live id whose submit age (`now_ns - submit_ts`,
    /// saturating — a clock running backwards never expires) strictly
    /// exceeds `max_pending_ns` drains exactly like [`Self::finish`]
    /// (retained truth emits when present, else
    /// [`Terminal::Unknown`] + [`ReducerStats::unfinished`]),
    /// tombstoned, in ascending id order. Ids at exactly the bound
    /// stay live (the deadline is inclusive). The equation holds
    /// across calls: `admitted == emitted + live`,
    /// `unfinished ⊆ emitted`.
    pub fn expire_before(&mut self, now_ns: u64, max_pending_ns: u64) -> Vec<RequestRecord> {
        let stale: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| now_ns.saturating_sub(p.submit_ts) > max_pending_ns)
            .map(|(id, _)| *id)
            .collect();
        self.drain_ids(stale)
    }

    /// Drains the given pending ids in ascending id order: ids with
    /// retained terminal truth emit it; the rest emit
    /// [`Terminal::Unknown`] with no duration and count as
    /// [`ReducerStats::unfinished`]. Drained ids are tombstoned.
    /// Shared by [`Self::finish`] (all ids) and
    /// [`Self::expire_before`] (stale ids) — one drain path, one
    /// accounting rule.
    fn drain_ids(&mut self, mut ids: Vec<u64>) -> Vec<RequestRecord> {
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
            self.tombstone(id, record.terminal, false);
            self.stats.emitted += 1;
            out.push(record);
        }
        out
    }

    /// Drains every pending id in ascending id order: ids with
    /// retained terminal truth emit it; the rest emit
    /// [`Terminal::Unknown`] with no duration and count as
    /// [`ReducerStats::unfinished`]. `stop_ns` is currently unused
    /// (reserved for future drain labeling); reconciliation depends
    /// only on observed edges. Drained ids are tombstoned. A second
    /// call emits nothing.
    pub fn finish(&mut self, _stop_ns: u64) -> Vec<RequestRecord> {
        let ids: Vec<u64> = self.pending.keys().copied().collect();
        self.drain_ids(ids)
    }
}
