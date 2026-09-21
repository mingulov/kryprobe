// SPDX-License-Identifier: GPL-3.0-or-later
//! BPF object discovery (1A-M10): pin-checked locator tiers.

use kryprobe_core::error::{BackendError, UnsupportedReason};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
// Pinned release-object digests (H-SEC-01), baked by build.rs from
// `KRYPROBE_PIN_DIGESTS`; empty in dev builds (pin check skipped).
include!(concat!(env!("OUT_DIR"), "/pinned_digests.rs"));

/// kcrypto object file name (tier-1 dir join + tier-2 bundled path).
const OBJECT_FILE_NAME: &str = "kcrypto.bpf.o";

/// Dev-object fallback, CWD-relative (tier 3; the K2 doctor spelling, kept
/// verbatim so dev runs from the workspace root keep working).
const DEV_OBJECT: &str = "target/kryprobe-bpf/kcrypto.bpf.o";

/// One tried candidate plus its exact fs error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocateMiss {
    /// Candidate path tried.
    pub candidate: PathBuf,
    /// Exact `fs::read` error text for this candidate.
    pub error: String,
}

/// Total locator miss: every candidate tried in order with exact fs errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectLocateError {
    /// Probed `KRYPROBE_BPF_DIR` value (`None` when unset).
    pub env_dir: Option<String>,
    /// Tried candidates in try order, each with its exact fs error.
    pub misses: Vec<LocateMiss>,
}

impl std::fmt::Display for ObjectLocateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let misses = self
            .misses
            .iter()
            .map(|miss| format!("{}: {}", miss.candidate.display(), miss.error))
            .collect::<Vec<_>>()
            .join("; ");
        write!(
            f,
            "object missing (tried KRYPROBE_BPF_DIR={}, {})",
            self.env_dir.as_deref().unwrap_or("(unset)"),
            misses
        )
    }
}

impl std::error::Error for ObjectLocateError {}

/// Object candidates in D2 try order, pure over the inputs (unit-testable
/// without env mutation): `KRYPROBE_BPF_DIR` (a file tried as-is, else a
/// dir joined with `kcrypto.bpf.o`) → executable-dir
/// `kryprobe-bpf/kcrypto.bpf.o` (bundled; skipped when the exe dir is
/// unknown, never fabricated) → the CWD-relative dev object.
///
/// When `elevated`, env and CWD tiers are refused (H-SEC-01): only the
/// exe-bundled tier is returned, possibly nothing.
#[must_use]
pub fn kcrypto_object_candidates(
    env: Option<&str>,
    exe_dir: Option<&Path>,
    elevated: bool,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !elevated && let Some(value) = env {
        let candidate = PathBuf::from(value);
        if candidate.is_file() {
            out.push(candidate);
        } else {
            out.push(candidate.join(OBJECT_FILE_NAME));
        }
    }
    if let Some(dir) = exe_dir {
        out.push(dir.join("kryprobe-bpf").join(OBJECT_FILE_NAME));
    }
    if !elevated {
        out.push(PathBuf::from(DEV_OBJECT));
    }
    out
}

/// Lowercase hex sha256 of bytes (H-SEC-01 pin check; G6 M1
/// versions also hash the spine object through it).
pub fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0xf) as usize] as char);
    }
    hex
}

/// Whether the baked pin set is non-empty, i.e. the object pin
/// check actually enforces (G6 fail-open observability; surfaced by
/// `doctor --versions`).
#[must_use]
pub fn pins_enforced() -> bool {
    !PINNED_DIGESTS.is_empty()
}

/// Warning text for the empty-pin skip (G6): the fail-open state is
/// named at runtime instead of silent. Pure over the flag for tests.
pub(crate) fn pin_skip_warning(pins_empty: bool) -> Option<&'static str> {
    pins_empty.then_some(
        "kryprobe: BPF object pin check SKIPPED (empty PINNED_DIGESTS dev build); \
         set KRYPROBE_PIN_DIGESTS at compile time or KRYPROBE_REQUIRE_PINS=1 to fail closed",
    )
}

/// Once-per-process guard for the pin-skip warning.
static PIN_SKIP_WARNED: AtomicBool = AtomicBool::new(false);

/// Pin check (H-SEC-01): empty pins (dev build) skip verification;
/// otherwise the object sha256 must be pinned. Pure over inputs for
/// unit tests; production passes [`PINNED_DIGESTS`].
pub(crate) fn verify_object_pinned(bytes: &[u8], pins: &[&str]) -> Result<(), String> {
    if pins.is_empty() {
        return Ok(());
    }
    let digest = sha256_hex(bytes);
    if pins.iter().any(|pin| *pin == digest) {
        Ok(())
    } else {
        Err(format!(
            "untrusted object (sha256 {digest} not in pinned release digests)"
        ))
    }
}

/// D2 consolidated locator, single-read form (replaces the probe/use
/// double-read, L-SEC-06): first readable AND pin-trusted candidate
/// wins; bytes return with the path so callers never re-open.
/// Untrusted (pin mismatch) candidates are misses, not errors.
pub fn locate_kcrypto_object_bytes() -> Result<(PathBuf, Vec<u8>), ObjectLocateError> {
    let elevated = crate::elevate::process_is_elevated();
    let env = std::env::var("KRYPROBE_BPF_DIR").ok();
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    let env_tier = if elevated { None } else { env.as_deref() };
    // G6: the empty-pin skip is fail-open by design (dev builds), so
    // it warns once per process instead of loading silently unpinned.
    if let Some(warning) = pin_skip_warning(PINNED_DIGESTS.is_empty())
        && !PIN_SKIP_WARNED.swap(true, Ordering::Relaxed)
    {
        eprintln!("{warning}");
    }
    let mut misses = Vec::new();
    for candidate in kcrypto_object_candidates(env_tier, exe_dir.as_deref(), elevated) {
        let bytes = match std::fs::read(&candidate) {
            Ok(bytes) => bytes,
            Err(err) => {
                misses.push(LocateMiss {
                    candidate,
                    error: err.to_string(),
                });
                continue;
            }
        };
        if let Err(detail) = verify_object_pinned(&bytes, PINNED_DIGESTS) {
            misses.push(LocateMiss {
                candidate,
                error: detail,
            });
            continue;
        }
        return Ok((candidate, bytes));
    }
    if elevated {
        misses.push(LocateMiss {
            candidate: PathBuf::from("(refused: env/CWD tiers disabled when elevated)"),
            error: "refused".to_owned(),
        });
    }
    Err(ObjectLocateError {
        env_dir: env,
        misses,
    })
}

/// Pin-trusted kcrypto object identity for `doctor --versions`
/// (G6 M1): path plus sha256 of the winning locator candidate.
/// `None` when no trusted object is present (environmental —
/// unprivileged shells without a dev object, or a pinned release
/// refusing every candidate).
#[must_use]
pub fn locate_kcrypto_object_identity() -> Option<(PathBuf, String)> {
    let (path, bytes) = locate_kcrypto_object_bytes().ok()?;
    Some((path, sha256_hex(&bytes)))
}

/// Read the kcrypto BPF object via the consolidated locator.
/// Missing/unreadable is `Unsupported` (environmental — the backend cannot
/// attach, honestly reported, never a defect). The reason name is the K2
/// spelling (stable surface).
pub(crate) fn kcrypto_object_bytes() -> Result<Vec<u8>, BackendError> {
    let (_path, bytes) = locate_kcrypto_object_bytes().map_err(|err| {
        BackendError::Unsupported(UnsupportedReason::with_detail(
            "kcrypto_object_unreadable",
            &err.to_string(),
        ))
    })?;
    Ok(bytes)
}
