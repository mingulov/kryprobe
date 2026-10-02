// SPDX-License-Identifier: GPL-3.0-or-later
//! ctx-v1 context-observation construction (ADR-0008 §(g)): fold one
//! `KCTX` row into a bucketed observation. Unknown-context rows (zero
//! cgroup or zero lifetime) land in [`CtxBucket::Unknown`] — they never
//! become host workload rows and never merge with observed rows.

use kryprobe_abi::kcrypto_ctx::{KCtxKey, VCtx};

/// Where one folded `KCTX` row belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CtxBucket {
    /// Observed context: cgroup and lifetime both read.
    Context,
    /// Unknown context: unreadable cgroup or lifetime. Explicitly not
    /// the host workload.
    Unknown,
    /// Host workload (reserved for future host-attributed rows; no
    /// ctx-v1 row maps here implicitly).
    Host,
}

/// One context-qualified observation: the folded counters plus their
/// bucket. Identity fields ride the key, not this struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtxObservation {
    /// The bucket this row belongs to.
    pub bucket: CtxBucket,
    /// Folded calls.
    pub calls: u64,
    /// Folded bytes.
    pub bytes: u64,
    /// Folded ok/errors/queued.
    pub ok: u64,
    /// Folded errors.
    pub errors: u64,
    /// Folded queued.
    pub queued: u64,
    /// Folded first/last stamps.
    pub first_ns: u64,
    /// Folded last stamp.
    pub last_ns: u64,
}

/// Build the observation for one folded `KCTX` row. Bucket rule: zero
/// `cgroup` or zero `start_ns` means unreadable, hence `Unknown`;
/// anything else with both fields read is `Context`. `Host` is never
/// inferred — there is no path from a ctx-v1 row to the host bucket.
#[must_use]
pub fn ctx_observation(key: &KCtxKey, folded: &VCtx) -> CtxObservation {
    let bucket = if key.cgroup == 0 || key.start_ns == 0 {
        CtxBucket::Unknown
    } else {
        CtxBucket::Context
    };
    CtxObservation {
        bucket,
        calls: folded.calls,
        bytes: folded.bytes,
        ok: folded.ok,
        errors: folded.errors,
        queued: folded.queued,
        first_ns: folded.first_ns,
        last_ns: folded.last_ns,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(cgroup: u64, start_ns: u64) -> KCtxKey {
        KCtxKey {
            kh: 7,
            cgroup,
            tgid: 1000,
            uid: 1000,
            start_ns,
        }
    }

    fn folded() -> VCtx {
        VCtx {
            calls: 5,
            bytes: 2560,
            ok: 5,
            errors: 0,
            queued: 0,
            first_ns: 1,
            last_ns: 2,
        }
    }

    #[test]
    fn observed_row_is_context() {
        let obs = ctx_observation(&key(100, 555), &folded());
        assert_eq!(obs.bucket, CtxBucket::Context);
        assert_eq!((obs.calls, obs.bytes), (5, 2560));
    }

    #[test]
    fn unreadable_fields_are_unknown_never_host() {
        assert_eq!(
            ctx_observation(&key(0, 555), &folded()).bucket,
            CtxBucket::Unknown
        );
        assert_eq!(
            ctx_observation(&key(100, 0), &folded()).bucket,
            CtxBucket::Unknown
        );
        assert_eq!(
            ctx_observation(&key(0, 0), &folded()).bucket,
            CtxBucket::Unknown
        );
        for obs in [key(0, 555), key(100, 0), key(0, 0)].map(|k| ctx_observation(&k, &folded())) {
            assert_ne!(obs.bucket, CtxBucket::Host);
            assert_ne!(obs.bucket, CtxBucket::Context);
        }
    }
}
