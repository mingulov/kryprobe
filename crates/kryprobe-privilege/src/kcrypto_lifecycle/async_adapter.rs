// SPDX-License-Identifier: GPL-3.0-or-later
//! Qualified asynchronous terminal completion: the callback adapter (P4/T09).
//!
//! # Contract v1 (written before implementation; tests pin every clause)
//!
//! ## 1. Named qualified sites (source/alias/lifetime-qualified)
//!
//! Exactly two completion functions are qualified. Any other completion
//! path (AF_ALG callbacks, crypto_engine consumers, unknown drivers)
//! stays `Queued`/`Unknown` with no terminal latency — explicit
//! unavailability, never a fabricated terminal.
//!
//! | Site | Module | Symbol | Prototype (BTF-pinned) | Key derivation |
//! |---|---|---|---|---|
//! | Cryptd | `cryptd` | `cryptd_skcipher_complete` | `void (struct skcipher_request *, int, crypto_completion_t)` | arg0 IS the submit-time request (identity, no chase) |
//! | Fixture | `kcrypto_fixture` | `kxc_complete` | `void (void *, int)` | `*(data + op_req_off)` chased BPF-side at the arm-resolved offset |
//!
//! Source proof (exact-version `crypto/cryptd.c`, audit note §3):
//! `cryptd_skcipher_enqueue` sets `req->base.data = req` and enqueues
//! `&req->base`; the worker's `complete(base->data, …)` reaches
//! `cryptd_skcipher_complete(req, …)` with the ORIGINAL request
//! pointer. Alias qualification: both symbols are `static` in their
//! module — exactly one definition each, module-BTF-qualified, with
//! `ProtoShape` validation refusing any signature drift at resolve
//! time. `crypto_request_complete`/`skcipher_request_complete` are
//! `static inline` (no BTF entry) and cannot be hooked; `complete()`
//! and workqueue functions are generic (unqualifiable) and are NOT
//! hooked.
//!
//! ## 2. Typed argument identity
//!
//! - Cryptd: arg0 `struct skcipher_request *` (BTF-typed deref proven
//!   live: `args->req->cryptlen` reads; A1 `@len[16]`), arg1 `int`
//!   native status, arg2 the re-arm completion (opaque to the
//!   adapter — read never).
//! - Fixture: arg0 `void *` = `struct kxc_op *` (the consumer's op;
//!   `op->req` is the request), arg1 `int` native status. The
//!   `op->req` offset is BTF-resolved from the fixture module at arm
//!   (`struct kxc_op.req`, currently the 3rd pointer — never
//!   hardcoded); the member must be a pointer to STRUCT
//!   `skcipher_request` or the arm refuses.
//! - Generic `void *data` is NEVER treated as a request pointer: the
//!   fixture site chases exactly one proven member; anything else is
//!   unqualified.
//!
//! ## 3. Request ownership and lifetime
//!
//! The request is owned by the submitter until terminal truth lands
//! (crypto API contract: the waiter holds the request across
//! `-EINPROGRESS`). The adapter treats submitter storage as BORROWED:
//! it copies the key (pointer value) into the identity relation and
//! never dereferences request memory userspace-side. Storage reuse
//! after terminal truth is EXPECTED (see §7); reuse while live is
//! caller confusion and resolves LOUD (ambiguity gaps), never by
//! misjoin.
//!
//! ## 4. Return classifications (adapter-owned; reducer infers nothing)
//!
//! Source: `crypto_enqueue_request` (`crypto/algapi.c`, byte-identical
//! both kernels) as passed through by `cryptd_enqueue_request` and
//! the fixture's `kxc_async_crypt`:
//!
//! | Native return | Condition | Disposition | Meaning |
//! |---|---|---|---|
//! | `-EINPROGRESS` | — | `Queued` | accepted; terminal arrives via callback (or retention proves it missing) |
//! | `-EBUSY` | submit carried `CRYPTO_TFM_REQ_MAY_BACKLOG` (`0x400` in P3 `req_flags`) | `Queued` | accepted on backlog; progress + terminal arrive via callback |
//! | `-EBUSY` | no `MAY_BACKLOG` (or flags unknown) | `Unresolved` | no source path produces this; loud, never completes (T06 design:71 preserved for unqualified paths) |
//! | `-ENOSPC` | — | `Terminal` | queue full without backlog: NOT queued, immediate error, no callback will ever arrive — exact errno preserved, never rewritten to `EBUSY` |
//! | anything else (0, positive, sync error) | — | `Terminal` | synchronous result with that exact status |
//!
//! ## 5. Progress vs terminal callbacks
//!
//! | Callback status | Disposition | Meaning |
//! |---|---|---|---|
//! | `-EINPROGRESS` | `Progress` | backlog-progress notification (cryptd worker + engine pump both emit `complete(backlog, -EINPROGRESS)` before the head terminal); never completes, never wakes the waiter |
//! | anything else | `Terminal` | the final result with that exact status |
//!
//! There is no `Unresolved` callback from a qualified site: every
//! status classifies. (Corrupt/foreign callback records refuse at
//! twin validation, before classification.)
//!
//! ## 6. Early callback (callback before return)
//!
//! Legal (a fast worker may complete before the submitter's exit run
//! records). The relation covers every submit from admission (§8), so
//! the early callback joins its token and its truth is RETAINED; the
//! later `-EINPROGRESS` return joins (by invocation, as always) and
//! the retained terminal emits. First terminal truth wins; a later
//! contradictory return is counted ambiguous, never re-emitted.
//!
//! ## 7. Reuse-in-callback (storage reuse before unwind)
//!
//! The callback may run while the submitter still unwinds, and the
//! submitter may re-admit the SAME storage for a new call before the
//! old return lands. Pairing stays distinct by construction:
//! - Returns join by BPF invocation id (per-call cookies), never by
//!   key — the old return CANNOT alias onto the new call.
//! - The relation maps key → live-token QUEUE: a second live token
//!   under one key makes that key AMBIGUOUS. A callback naming an
//!   ambiguous key gaps EVERY live token under it
//!   (`IdentityAmbiguous`) and is consumed — genuinely unattributable
//!   evidence must be loud, never guessed.
//! - A terminal callback moves its token live → tombstoned, so the
//!   normal reuse order (terminal, then resubmit, then old return)
//!   rejoins cleanly: the new submit finds no live rival.
//! - Sync nesting (same storage, inner completes first) is undisturbed:
//!   no callback arrives, both returns join by invocation, both
//!   tokens retire normally. Ambiguity fires ONLY when a callback
//!   names a key with ≥2 live tokens.
//!
//! ## 8. The identity relation (bounded, private)
//!
//! `AsyncAdapter` holds key → live-token queues plus per-key
//! tombstones. Insert at every submit (cover from admission —
//! early callbacks must join); remove live on sync-terminal return,
//! on terminal callback (→ tombstone), and on gap (→ tombstone).
//! `Queued` and `Unresolved` returns KEEP cover (terminal truth may
//! still arrive; an `Unresolved` return followed by a terminal
//! callback drains WITH truth at `finish`).
//!
//! Bounds (both pools sized by the DECODER's capacity — one number,
//! two pools; no separate knob without data: `decode_capacity` is
//! already envelope-sized, and exhaustion is counted + loud when a
//! burst exceeds it):
//! - Live tokens are NEVER evicted: insert past capacity refuses
//!   COVER for the new submit (counted `cover_refused`) — the submit
//!   itself stays valid (sync completion still works); its future
//!   callbacks arrive as counted orphans. Refusing cover is honest
//!   backpressure; evicting live tokens would manufacture orphans.
//! - Tombstones FIFO-evict past capacity (counted
//!   `tombstone_evictions`); a late callback past eviction is a
//!   counted orphan. At most one terminal record per invocation,
//!   including late callbacks after retention expiry (the reducer's
//!   tombstone diagnoses repeats vs contradictions; evicted history
//!   reads orphan — reducer contract, unchanged).
//!
//! Callback dispatch for key K naming token set S (live) / D (dead):
//! - |S| == 1 → join it (emit `Edge::Callback` for the token; the
//!   reducer decides emission vs diagnosis).
//! - |S| > 1 → gap every token in S (`IdentityAmbiguous`), consume
//!   the callback, count `ambiguous_keys` (then tombstone all, so a
//!   late callback rejoins instead of gapping again).
//! - |S| == 0, D nonempty → join the NEWEST tombstone (the reducer
//!   diagnoses the late callback against emitted truth).
//! - S and D empty → counted orphan (`callback_orphans`), no edge.
//!
//! Stale defense (decoder-symmetric): each live token pins its
//! submit timestamp; a callback PREDATING its submit is twin drift
//! (causality + shared ktime clock forbid it honestly) — consumed
//! as `stale_callbacks`, never joined, cover kept. Transport
//! reorder (callback arriving before its submit edge) reads as
//! orphan: no callback buffering, same as the decoder's
//! no-return-buffering discipline.
//!
//! Adapter pointers are NEVER rewritten: the relation only READS the
//! callback key. No callback pointer is modified, ever.
//!
//! ## 9. Module lifetime
//!
//! Callback sites are OPTIONAL (unlike the 7 required fsession
//! sites): attach-if-present, never fail bring-up. Missing module
//! BTF (cryptd/fixture not loaded) skips the program (recorded in
//! `points`, sensor runs submit/return-only; queued invocations
//! drain `Unknown` honestly). Module present but prototype drifted →
//! resolve refuses THAT site (loud, recorded); present but fixture
//! `op->req` unresolvable → ARM refuses (fail-closed twin drift —
//! absence is quiet, unreadability is loud). Unload between attach
//! and arm lands in `LLOSS_DISABLED` (counted). The fixture program
//! gates on the arm-resolved presence word (0 = drop to
//! `LLOSS_DISABLED`, never chase offset 0 as data — wait, no:
//! presence-gated, so offset 0 with presence set still chases
//! correctly; see the LCFG v5 layout).
//!
//! ## 10. Loss behavior (every class counted, mapped to frozen fields)
//!
//! | Adapter event | Counter | Integrity mapping (frozen `IntegritySummary`) |
//! |---|---|---|
//! | cover refused (live pool full) | `cover_refused` | `state_insert_failures` (evidence failed to enter join state) |
//! | unmappable callback (no live/dead token) | `callback_orphans` | `unmatched_returns` (completion observed, joinable to nothing) |
//! | ambiguous-key gap storm (|S|>1) | `ambiguous_keys` (+ per-id reducer gaps) | `correlation_overflows` |
//! | tombstone FIFO eviction | `tombstone_evictions` | `state_evictions` (the field exists for bounded-table eviction; previously zero-input) |
//! | stale callback (predates its submit — twin drift) | `stale_callbacks` | `correlation_overflows` |
//!
//! No new public/JSON fields: the ledger carries internal
//! `AdapterStats` (like T07's `TfmStats`); the backend maps them into
//! the frozen summary; P6 owns any user-visible emission.
//!
//! ## 11. Wire and loader shape (hookup, all-or-nothing twins)
//!
//! - `LEdge` stays v6, 112 bytes, SAME fields (no `FIELDS` change):
//!   callback halves ride `edge = LEDGE_CALLBACK (3)` with
//!   `site ∈ {LSITE_CB_CRYPTD (3), LSITE_CB_KXC (4)}`, `flags == 0`
//!   (never tainted — no cookie to lose; never truncated — no name),
//!   `key != 0` (the request), `status` = native err (any `i32`),
//!   `invoc == 0` (names no fsession invocation — the relation
//!   joins by key), zero metadata words, `tfm == 0`, empty `drv`
//!   (returns' R2 discipline extended: callback halves never chase
//!   submit-owned facts). Old decoders refuse kind 3 as `BadEdge`
//!   (fail-closed); no version bump (shape-identical enum extension).
//! - `LConfig` v4 → v5: `op_req_off@48` + `op_req_present@52`
//!   (fixture `op->req` BTF offset + T08-`refcnt_present`-style
//!   presence word), `reserved[8]@56`. BPF pins v5 (older configs
//!   disarm); loader pins v5 (readback-verified).
//! - Hook lanes grow 16 → 18 EXACTLY (`LAGG_CB_CRYPTD = 16`,
//!   `LAGG_CB_KXC = 17`; `LLOSS` 5×16 → 5×18 = 90 entries; lanes
//!   12/13 stay T10's aead-alloc reservation; no headroom — every
//!   lane has exactly one writer). `LCTR` unchanged (callbacks don't
//!   mint). Userspace tallies (`edge_hits`, `agg_accepted`,
//!   baselines) widen 16 → 18 with the equation extended per-lane.
//! - Loader: `fentry/` sections admitted for the two EXACT callback
//!   symbols (no open prefix); module-BTF id resolution
//!   (`/sys/kernel/btf/<module>`) + `attach_btf_obj_fd` at load;
//!   `max_programs` 7 → 9; optional-site gate (required sites still
//!   all-or-nothing; callback sites attach-if-present, recorded in
//!   `points`).
//! - BPF: two `fentry` programs (no session kfuncs — plain entry
//!   args; R4 call-free; shared gated emitter). Cryptd program:
//!   key = arg0. Fixture program: presence-gate, then
//!   key = `*(u64 *)(arg0 + op_req_off)` via `probe_read`
//!   (fault → `LLOSS_BADKEY`, never a wild key).
//!
//! ## 12. Fixture (adapter rows only)
//!
//! - Worker mirrors the real dispatchers: `kxc_async_fn` emits
//!   `complete(backlog, -EINPROGRESS)` (via `crypto_get_backlog`)
//!   before each dequeue-complete — the cryptd.c/engine shape,
//!   source-cited. `kxc_complete` splits progress (`-EINPROGRESS` →
//!   progress row, no wake) vs terminal (terminal row + wake).
//!   fixture.h's "never a kernel callback" line is amended; the
//!   `guest_ledger` backlog-accepted contract gains the deterministic
//!   progress rows (reqs 1..3: `progress_errno: Some(-115)`,
//!   notifications 2; order P1,T0,P2,T1,P3,T2,T3).
//! - New scenario `no-backlog-burst`: held queue + 2 submits WITHOUT
//!   `MAY_BACKLOG` → `-EINPROGRESS` then `-ENOSPC` (immediate,
//!   terminal, no callback) — the live ENOSPC proof.
//! - (A3, if needed) scenario `cryptd-async`: in-kernel
//!   `CRYPTO_ALG_ASYNC`-masked alloc attempt + traffic — the 7.2
//!   avenue probe; truth or refusal, receipted.
//!
//! ## 13. Q03–Q08 coverage map
//!
//! Reducer characterization (green day one — T05/T06 built the
//! semantics; T09 pins them as table cases, proving "disposition
//! feed only" needs NO reducer change): cross-CPU terminal,
//! callback-before-return, callback-triggered reuse, backlog
//! progress, sync-on-async-capable, missing/late/duplicate/
//! conflicting/orphan. Adapter RED (fails until implemented):
//! return classification incl. `MAY_BACKLOG`-gated `EBUSY` and exact
//! `ENOSPC`; callback classification; relation insert/remove/
//! dispatch/exhaustion/tombstone rules; decode twin rules for kind 3;
//! sensor ingest + ledger/equation widening. Live (guest cells):
//! fixture async/burst/no-backlog on both kernels; real cryptd
//! (7.0.14 proven, 7.2.6 per audit decision tree); 6.12 refusal.

use kryprobe_core::kcrypto::{CallbackDisposition, Edge, GapReason, ReturnDisposition};
use std::collections::{HashMap, VecDeque};

/// `CRYPTO_TFM_REQ_MAY_BACKLOG` (`include/linux/crypto.h:152`,
/// `0x400` — verified identical in the v7.0.14 and v7.2.6 stable
/// sources; the fixture sets this bit from its own kernel headers,
/// and the live burst cell pins the value end to end).
pub const CRYPTO_TFM_REQ_MAY_BACKLOG: u32 = 0x0000_0400;

// NOTE: the typed `AdapterSite` enum (Cryptd | Fixture) lands with
// the ABI wire consts + decode twin (wave A) — dispatch takes no
// site (both sites share the relation; per-site rules are YAGNI).

/// Classify a native function-return status per contract §4.
/// `req_flags` is the submit's P3 entry-side flags word (`None` when
/// the entry chase was unreadable — unknown flags never imply
/// backlog consent).
#[must_use]
pub fn classify_return(status: i32, req_flags: Option<u32>) -> ReturnDisposition {
    if status == -libc::EINPROGRESS {
        ReturnDisposition::Queued
    } else if status == -libc::EBUSY {
        match req_flags {
            Some(flags) if flags & CRYPTO_TFM_REQ_MAY_BACKLOG != 0 => ReturnDisposition::Queued,
            _ => ReturnDisposition::Unresolved,
        }
    } else {
        // Every other status — 0, positive, a sync error, and
        // `-ENOSPC` (queue full without backlog: NOT queued, no
        // callback will ever arrive) — is terminal with that exact
        // status. `-ENOSPC` rides this arm deliberately: no rewrite,
        // no special case, exact errno preserved.
        ReturnDisposition::Terminal
    }
}

/// Classify a native callback status per contract §5.
#[must_use]
pub fn classify_callback(status: i32) -> CallbackDisposition {
    if status == -libc::EINPROGRESS {
        CallbackDisposition::Progress
    } else {
        CallbackDisposition::Terminal
    }
}

/// Cumulative adapter loss counters (contract §10; internal ledger
/// feed — the backend maps these into the frozen integrity summary).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdapterStats {
    /// Submits admitted without relation cover (live pool full).
    pub cover_refused: u64,
    /// Callbacks naming no live or tombstoned token.
    pub callback_orphans: u64,
    /// Callbacks naming an ambiguous key (|live| > 1; every live
    /// token gapped).
    pub ambiguous_keys: u64,
    /// Tombstone FIFO evictions past capacity.
    pub tombstone_evictions: u64,
    /// Callbacks predating their submit (twin drift — causality
    /// forbids it honestly; reorder reads as orphan instead).
    pub stale_callbacks: u64,
}

/// Bounded private identity relation between adapter keys (request
/// pointers, pairing material — never rendered, never leaves
/// privilege) and invocation tokens (contract §8).
#[derive(Debug)]
pub struct AsyncAdapter {
    /// Maximum live tokens (insert refuses cover past this).
    live_cap: usize,
    /// Maximum tombstoned tokens (FIFO eviction past this).
    dead_cap: usize,
    /// Key → live tokens oldest-first (len > 1 = ambiguous key).
    live: HashMap<u64, VecDeque<u64>>,
    /// Live token → submit timestamp (stale defense: a callback
    /// predating its submit is twin drift, never joined).
    submit_ts: HashMap<u64, u64>,
    /// Key → tombstoned tokens oldest-first (late-callback joins).
    dead: HashMap<u64, VecDeque<u64>>,
    /// Global tombstone order oldest-first (FIFO eviction).
    dead_order: VecDeque<(u64, u64)>,
    /// Live token count (sum of live queue lengths).
    live_count: usize,
    /// Tombstone count (dead_order length).
    dead_count: usize,
    /// Loss counters.
    stats: AdapterStats,
}

impl AsyncAdapter {
    /// New adapter with both pools sized by `capacity` (contract §8:
    /// one number, two pools — live insert-refuse, dead FIFO-evict).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            live_cap: capacity,
            dead_cap: capacity,
            live: HashMap::new(),
            submit_ts: HashMap::new(),
            dead: HashMap::new(),
            dead_order: VecDeque::new(),
            live_count: 0,
            dead_count: 0,
            stats: AdapterStats::default(),
        }
    }

    /// Current loss counters.
    #[must_use]
    pub fn stats(&self) -> AdapterStats {
        self.stats
    }

    /// Move `token` under `req_key` live → tombstoned (no-op when the
    /// token holds no live cover — never covered, or already
    /// retired). Evicts the oldest tombstone past capacity (counted).
    fn retire(&mut self, req_key: u64, token: u64) {
        let Some(queue) = self.live.get_mut(&req_key) else {
            return;
        };
        let Some(pos) = queue.iter().position(|t| *t == token) else {
            return;
        };
        queue.remove(pos);
        if queue.is_empty() {
            self.live.remove(&req_key);
        }
        self.live_count -= 1;
        self.submit_ts.remove(&token);
        self.dead.entry(req_key).or_default().push_back(token);
        self.dead_order.push_back((req_key, token));
        self.dead_count += 1;
        self.evict_dead_if_over();
    }

    /// FIFO-evict tombstones past capacity (counted): the oldest
    /// retention expires first; late callbacks past expiry read
    /// orphan.
    fn evict_dead_if_over(&mut self) {
        while self.dead_count > self.dead_cap {
            let Some((old_key, old_token)) = self.dead_order.pop_front() else {
                break;
            };
            if let Some(queue) = self.dead.get_mut(&old_key) {
                if let Some(pos) = queue.iter().position(|t| *t == old_token) {
                    queue.remove(pos);
                }
                if queue.is_empty() {
                    self.dead.remove(&old_key);
                }
            }
            self.dead_count -= 1;
            self.stats.tombstone_evictions += 1;
        }
    }

    /// Cover a fresh submit: push `token` onto key `req_key`'s live
    /// queue and pin its submit timestamp (refuse cover — counted —
    /// past live capacity; the submit itself is unaffected).
    pub fn note_submit(&mut self, req_key: u64, token: u64, submit_ts: u64) {
        if self.live_count >= self.live_cap {
            self.stats.cover_refused += 1;
            return;
        }
        self.live.entry(req_key).or_default().push_back(token);
        self.submit_ts.insert(token, submit_ts);
        self.live_count += 1;
    }

    /// A sync-terminal return for `token` under `req_key`: tombstone
    /// it — late callbacks after a sync return diagnose against the
    /// reducer tombstone, never orphan.
    pub fn note_sync_return(&mut self, req_key: u64, token: u64) {
        self.retire(req_key, token);
    }

    /// A gap completing `token` under `req_key`: tombstone it — late
    /// callbacks still diagnose against the gap completion.
    pub fn note_gap(&mut self, req_key: u64, token: u64) {
        self.retire(req_key, token);
    }

    /// Resolve a callback naming `req_key` to its join action
    /// (contract §8 dispatch): exactly-one-live joins (terminal
    /// callbacks retire live → dead; progress never retires),
    /// multi-live gaps-all, newest-dead re-joins for diagnosis,
    /// else a counted orphan. A callback predating its submit is
    /// twin drift (causality: the callback is caused by the submit,
    /// so its timestamp cannot precede it on the shared ktime
    /// clock): consumed as stale, never joined. Emits zero or more
    /// edges (the callback edge and/or identity gaps). Transport
    /// reorder (callback arriving before its submit edge) reads as
    /// orphan — no callback buffering, same as the decoder's
    /// no-return-buffering discipline.
    pub fn resolve_callback(&mut self, req_key: u64, ts_ns: u64, status: i32) -> Vec<Edge> {
        let live_len = self.live.get(&req_key).map_or(0, VecDeque::len);
        if live_len > 1 {
            let tokens: Vec<u64> = self.live.remove(&req_key).unwrap_or_default().into();
            let mut out = Vec::with_capacity(tokens.len());
            for token in tokens {
                self.live_count -= 1;
                self.submit_ts.remove(&token);
                self.dead.entry(req_key).or_default().push_back(token);
                self.dead_order.push_back((req_key, token));
                self.dead_count += 1;
                out.push(Edge::Gap {
                    id: token,
                    reason: GapReason::IdentityAmbiguous,
                });
            }
            self.evict_dead_if_over();
            self.stats.ambiguous_keys += 1;
            return out;
        }
        if live_len == 1 {
            let token = self.live[&req_key][0];
            match self.submit_ts.get(&token) {
                Some(&submit) if ts_ns < submit => {
                    // Predates its submit: twin drift (replay with
                    // scrambled timestamps, never honest transport —
                    // honest reorder preserves timestamp order).
                    // Consumed, counted, never joined; the live token
                    // keeps its cover (its real callback may follow).
                    // No debug_assert: drift defense is a legitimate
                    // runtime path, exercised by tests.
                    self.stats.stale_callbacks += 1;
                    return Vec::new();
                }
                None => {
                    // Invariant break (live token without a submit
                    // timestamp): fail closed as stale, never join.
                    debug_assert!(false, "live token without submit ts");
                    self.stats.stale_callbacks += 1;
                    return Vec::new();
                }
                _ => {}
            }
            let disposition = classify_callback(status);
            if disposition == CallbackDisposition::Terminal {
                self.retire(req_key, token);
            }
            return vec![Edge::Callback {
                id: token,
                ts_ns,
                status,
                disposition,
            }];
        }
        if let Some(&token) = self.dead.get(&req_key).and_then(VecDeque::back) {
            let disposition = classify_callback(status);
            return vec![Edge::Callback {
                id: token,
                ts_ns,
                status,
                disposition,
            }];
        }
        self.stats.callback_orphans += 1;
        Vec::new()
    }
}
