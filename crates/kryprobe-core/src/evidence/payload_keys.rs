// SPDX-License-Identifier: GPL-3.0-or-later
//! `BackendPayload` key vocabulary (1B-H3 structural).
//!
//! The kcrypto row vocabulary as machine-checked consts: producers spell
//! payload keys and consumers read them through these consts, and the
//! `payload_contract` integration test pins the exact per-row key sets
//! against production `decode` output. Rules:
//!
//! - A producer adding a key extends the row set here AND the test's
//!   pinned set — an unlisted key fails the contract test.
//! - A consumer reading a key uses the const and lists it in its
//!   read-set (`POLICY_READ_KEYS` / `WATCH_READ_KEYS`) — a read outside
//!   the emitted sets fails the contract test.
//! - `MODULE` is the one policy-read key kcrypto never emits:
//!   import-shaped observations carry it; kcrypto gates it out (D4).

/// Row discriminator (`agg`/`totals`/`ident`/`who`).
pub const ROW: &str = "row";
/// FNV row hash joining agg and who rows.
pub const KEY_HASH: &str = "key_hash";
/// Cipher family name.
pub const FAMILY: &str = "family";
/// Operation name.
pub const OP: &str = "op";
/// Result-class name.
pub const RESULT: &str = "result";
/// Algorithm name.
pub const ALGORITHM: &str = "algorithm";
/// Driver name.
pub const DRIVER: &str = "driver";
/// Crypto context name.
pub const CONTEXT: &str = "context";
/// Kernel module (import-shaped observations only; kcrypto never emits).
pub const MODULE: &str = "module";
/// Tally block (`COUNT_KEYS`).
pub const COUNTS: &str = "counts";
/// Call tally (top-level on who rows, nested under `counts` elsewhere).
pub const CALLS: &str = "calls";
/// Ok tally.
pub const OK: &str = "ok";
/// Error tally.
pub const ERRORS: &str = "errors";
/// Queued tally.
pub const QUEUED: &str = "queued";
/// Byte tally.
pub const BYTES: &str = "bytes";
/// Latency buckets (verbatim passthrough).
pub const LAT: &str = "lat";
/// Observation window block (`WINDOW_KEYS`).
pub const WINDOW: &str = "window";
/// Window/tallies first timestamp.
pub const FIRST_NS: &str = "first_ns";
/// Window/tallies last timestamp.
pub const LAST_NS: &str = "last_ns";
/// Status-canonical marker.
pub const STATUS_CANONICAL: &str = "status_canonical";
/// Inventory execution marker (agg, inventory decodes only).
pub const EXECUTION: &str = "execution";
/// Unobserved-result note (agg, `KRES_UNOBSERVED` only).
pub const RESULT_NOTE: &str = "result_note";
/// Ident marker kind (`ident`/`overflow`/`unknown`).
pub const IDENT_KIND: &str = "ident_kind";
/// Name-length block (`NAME_LENS_KEYS`).
pub const NAME_LENS: &str = "name_lens";
/// Algorithm name length.
pub const ALG: &str = "alg";
/// Driver name length.
pub const DRV: &str = "drv";
/// First-seen timestamp.
pub const FIRST_SEEN_NS: &str = "first_seen_ns";
/// Thread-group id.
pub const TGID: &str = "tgid";
/// Thread id.
pub const TID: &str = "tid";
/// Process command name.
pub const COMM: &str = "comm";
/// User id.
pub const UID: &str = "uid";
/// Cgroup id.
pub const CGROUP: &str = "cgroup";
/// Stack block (`STACK_KEYS`).
pub const STACK: &str = "stack";
/// Stack-table id (raw helper errno when negative).
pub const ID: &str = "id";
/// Symbolized frames (`FRAME_KEYS` each).
pub const FRAMES: &str = "frames";
/// Frame instruction pointer.
pub const IP: &str = "ip";
/// Frame symbol (`null` when unresolvable).
pub const SYM: &str = "sym";
/// Parent pid (who, resolved only).
pub const PPID: &str = "ppid";
/// Parent command name (who, resolved only).
pub const PCOMM: &str = "pcomm";
/// Crypto block size (who, params resolved only).
pub const BLOCKSIZE: &str = "blocksize";
/// Crypto IV size (who, params resolved only).
pub const IVSIZE: &str = "ivsize";
/// Minimum key size (who, params resolved only).
pub const MIN_KEYSIZE: &str = "min_keysize";
/// Maximum key size (who, params resolved only).
pub const MAX_KEYSIZE: &str = "max_keysize";
/// First non-queued errno (who, rendered only).
pub const FIRST_ERRNO: &str = "first_errno";
/// Capture profile on every row: which capture produced it.
pub const CAPTURE_PROFILE: &str = "capture_profile";
/// Count unit on counted rows: what one count means.
pub const COUNT_UNIT: &str = "count_unit";
/// Completion coverage on counted rows: whether terminal request
/// completion is observed by this capture.
pub const COMPLETION_COVERAGE: &str = "completion_coverage";

/// Capture-profile value: single-edge fexit API-return sensor
/// (T02; the only profile in v0.1).
pub const CAPTURE_API_RETURNS: &str = "api-returns";
/// Count-unit value: one API-invocation return, not one delivered
/// kernel operation and not one completed request.
pub const COUNT_API_INVOCATION_RETURN: &str = "api_invocation_return";
/// Completion-coverage value: terminal completion is not observed.
pub const COVERAGE_UNOBSERVED: &str = "unobserved";

/// Agg rows: always emitted.
pub const AGG_KEYS: &[&str] = &[
    ROW,
    KEY_HASH,
    FAMILY,
    OP,
    RESULT,
    ALGORITHM,
    DRIVER,
    CONTEXT,
    COUNTS,
    BYTES,
    LAT,
    WINDOW,
    STATUS_CANONICAL,
    CAPTURE_PROFILE,
    COUNT_UNIT,
    COMPLETION_COVERAGE,
];

/// Agg rows: emitted only when applicable.
pub const AGG_OPTIONAL_KEYS: &[&str] = &[EXECUTION, RESULT_NOTE];

/// Totals rows: always emitted, nothing optional.
pub const TOTALS_KEYS: &[&str] = &[
    ROW,
    COUNTS,
    BYTES,
    WINDOW,
    STATUS_CANONICAL,
    CAPTURE_PROFILE,
    COUNT_UNIT,
    COMPLETION_COVERAGE,
];

/// Ident rows: always emitted, nothing optional.
pub const IDENT_KEYS: &[&str] = &[
    ROW,
    IDENT_KIND,
    KEY_HASH,
    FAMILY,
    OP,
    RESULT,
    CONTEXT,
    NAME_LENS,
    FIRST_SEEN_NS,
    CAPTURE_PROFILE,
];

/// Who rows: always emitted.
pub const WHO_KEYS: &[&str] = &[
    ROW,
    KEY_HASH,
    TGID,
    TID,
    COMM,
    UID,
    CGROUP,
    STACK,
    CALLS,
    FIRST_NS,
    LAST_NS,
    CAPTURE_PROFILE,
];

/// Who rows: emitted only when resolved.
pub const WHO_OPTIONAL_KEYS: &[&str] = &[
    PPID,
    PCOMM,
    BLOCKSIZE,
    IVSIZE,
    MIN_KEYSIZE,
    MAX_KEYSIZE,
    FIRST_ERRNO,
];

/// `counts` block keys.
pub const COUNT_KEYS: &[&str] = &[CALLS, OK, ERRORS, QUEUED];

/// `window` block keys.
pub const WINDOW_KEYS: &[&str] = &[FIRST_NS, LAST_NS];

/// `name_lens` block keys.
pub const NAME_LENS_KEYS: &[&str] = &[ALG, DRV];

/// `stack` block keys.
pub const STACK_KEYS: &[&str] = &[ID, FRAMES];

/// One stack frame's keys.
pub const FRAME_KEYS: &[&str] = &[IP, SYM];

/// Every key any kcrypto row may emit, plus the policy-only `module`
/// (import-shaped). The contract test rejects emitted keys outside it.
pub const VOCAB: &[&str] = &[
    ROW,
    KEY_HASH,
    FAMILY,
    OP,
    RESULT,
    ALGORITHM,
    DRIVER,
    CONTEXT,
    MODULE,
    COUNTS,
    CALLS,
    OK,
    ERRORS,
    QUEUED,
    BYTES,
    LAT,
    WINDOW,
    FIRST_NS,
    LAST_NS,
    STATUS_CANONICAL,
    EXECUTION,
    RESULT_NOTE,
    IDENT_KIND,
    NAME_LENS,
    ALG,
    DRV,
    FIRST_SEEN_NS,
    TGID,
    TID,
    COMM,
    UID,
    CGROUP,
    STACK,
    ID,
    FRAMES,
    IP,
    SYM,
    PPID,
    PCOMM,
    BLOCKSIZE,
    IVSIZE,
    MIN_KEYSIZE,
    MAX_KEYSIZE,
    FIRST_ERRNO,
    CAPTURE_PROFILE,
    COUNT_UNIT,
    COMPLETION_COVERAGE,
];
