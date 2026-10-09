// SPDX-License-Identifier: GPL-3.0-or-later
//! Reviewed unprivileged host reads (spec §5.2): `/proc` identity/lifetime
//! checks and cgroupfs inode binding. Handle-based opening is ruled out
//! (it needs a DAC-search capability the helper never holds); binding is
//! a confined tree walk matching the captured cgroup id against live
//! directory inodes.
//!
//! Confinement rules:
//!
//! - Every read is rooted at an explicit `proc_root` / `cgroup_root`
//!   (`/proc` and `/sys/fs/cgroup` in production, fixtures in tests).
//! - Hint paths from `/proc/<tgid>/cgroup` must be absolute, lexically
//!   clean (no `.`, `..`, empty components, or NUL), and symlink-free at
//!   every component; namespace-relative or escaping hints refuse as
//!   [`HostReadError::NotHostPath`] and are never joined onto the host.
//! - The tree walk never follows symlinks (refused + counted) and never
//!   leaves the root device (mount crossings refused).
//! - All reads are bounded ([`MAX_CGROUP_SCAN_DIRS`],
//!   [`MAX_PID_FILE_BYTES`]); all errors are typed with numeric ids only
//!   — paths and file bytes never appear in diagnostics.
//! - Deletion or replacement mid-traversal refuses typed (`Gone…`,
//!   `ReuseDetected`) with the captured ids preserved; permission denial
//!   refuses typed (`Denied…`), never silently.

use crate::cache::HelperCounters;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Helper-local pin: maximum cgroup directories visited in one inode
/// scan. Exhaustion refuses [`HostReadError::BudgetExceeded`].
pub const MAX_CGROUP_SCAN_DIRS: usize = 4096;

/// Helper-local pin: maximum bytes read from one `/proc/<tgid>/` file.
pub const MAX_PID_FILE_BYTES: usize = 4096;

/// Helper-local pin: maximum hint components resolved in one confined
/// join (bounds per-key pid-phase work).
pub const MAX_HINT_COMPONENTS: usize = 256;

/// One `/proc/<tgid>/` observation: the cgroup hint plus the host
/// lifetime discriminator (task start time in boot clock ticks, an
/// opaque stability token — never equated with capture-domain
/// nanoseconds, only compared for equality within this host view).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PidEntry {
    /// Host thread-group id.
    pub tgid: u32,
    /// Raw cgroup hint from the `0::` line (unvalidated; confined at join).
    pub hint: String,
    /// Task start time in boot clock ticks (stability token).
    pub start_ticks: u64,
}

/// A live cgroup object bound by inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CgroupObject {
    /// The captured cgroup id this object was bound for.
    pub cgroup: u64,
    /// Device of the object (must equal the cgroup root device).
    pub dev: u64,
    /// Inode of the object (equals the cgroup id on cgroup v2).
    pub ino: u64,
}

/// Typed host-read failure. Displays carry numeric ids at most; paths and
/// file bytes never appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostReadError {
    /// The process was already gone.
    GonePid {
        /// Host thread-group id.
        tgid: u32,
    },
    /// A path vanished mid-traversal (concurrent deletion).
    GoneDuringScan,
    /// Permission denied reading the process.
    DeniedPid {
        /// Host thread-group id.
        tgid: u32,
    },
    /// Permission denied during the cgroup scan (coverage incomplete).
    DeniedCgroup {
        /// Captured cgroup id.
        cgroup: u64,
    },
    /// Lexically non-host path (relative, escaping, wrong shape) or a
    /// mount crossing: never a host object.
    NotHostPath,
    /// A symlink component refused (never followed).
    SymlinkRefused,
    /// Identity changed under us (pid reuse or object replacement).
    ReuseDetected,
    /// A scan/read budget was exceeded.
    BudgetExceeded,
    /// The host view is unusable (missing roots, cgroup v1-only, …).
    Unsupported,
    /// Malformed host content (bad stat/uptime shape, wrong node type).
    Invalid,
}

impl HostReadError {
    /// Fixed counter key for this failure (static, no input echo).
    #[cfg(test)]
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::GonePid { .. } | Self::GoneDuringScan => "gone",
            Self::DeniedPid { .. } | Self::DeniedCgroup { .. } => "denied",
            Self::NotHostPath => "not_host_path",
            Self::SymlinkRefused => "symlink_refused",
            Self::ReuseDetected => "reuse_detected",
            Self::BudgetExceeded => "budget_exceeded",
            Self::Unsupported => "unsupported",
            Self::Invalid => "invalid",
        }
    }
}

impl std::fmt::Display for HostReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GonePid { tgid } => write!(f, "process {tgid} is gone"),
            Self::GoneDuringScan => write!(f, "path vanished during traversal"),
            Self::DeniedPid { tgid } => write!(f, "permission denied reading process {tgid}"),
            Self::DeniedCgroup { cgroup } => {
                write!(f, "permission denied scanning for cgroup {cgroup}")
            }
            Self::NotHostPath => write!(f, "path is not a host cgroup path"),
            Self::SymlinkRefused => write!(f, "symlink component refused"),
            Self::ReuseDetected => write!(f, "identity changed during traversal"),
            Self::BudgetExceeded => write!(f, "host scan budget exceeded"),
            Self::Unsupported => write!(f, "host view is unsupported"),
            Self::Invalid => write!(f, "host content is malformed"),
        }
    }
}

impl std::error::Error for HostReadError {}

/// Rooted unprivileged host view.
#[derive(Debug, Clone)]
pub struct HostView {
    proc_root: PathBuf,
    cgroup_root: PathBuf,
}

impl HostView {
    /// Root a view at explicit directories (production: `/proc`,
    /// `/sys/fs/cgroup`; tests: fixtures).
    #[must_use]
    pub fn new(proc_root: &Path, cgroup_root: &Path) -> Self {
        Self {
            proc_root: proc_root.to_path_buf(),
            cgroup_root: cgroup_root.to_path_buf(),
        }
    }

    /// Execution-kernel scope tag `osrelease/boot_id` (the helper-local
    /// tag convention; capture must produce identical tags — Stage 1/3).
    /// Missing files refuse [`HostReadError::Unsupported`]; malformed or
    /// over-bound content refuses [`HostReadError::Invalid`].
    pub fn kernel_scope(&self) -> Result<String, HostReadError> {
        let release = read_bounded(&self.proc_root.join("sys/kernel/osrelease"))?;
        let boot_id = read_bounded(&self.proc_root.join("sys/kernel/random/boot_id"))?;
        let release = release.trim();
        let boot_id = boot_id.trim();
        for field in [release, boot_id] {
            if field.is_empty()
                || field.len() > 64
                || field
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
            {
                return Err(HostReadError::Invalid);
            }
        }
        let scope = format!("{release}/{boot_id}");
        if scope.len() > kryprobe_core::workload::MAX_KERNEL_IDENTITY_BYTES {
            return Err(HostReadError::Invalid);
        }
        Ok(scope)
    }

    /// Boot-relative monotonic nanoseconds from `/proc/uptime` (the
    /// validity/TTL clock domain; ~10 ms granularity, documented).
    pub fn boot_time_ns(&self) -> Result<u64, HostReadError> {
        let text = read_bounded(&self.proc_root.join("uptime"))?;
        parse_uptime_ns(&text).ok_or(HostReadError::Invalid)
    }

    /// Read one process entry: the cgroup v2 hint plus the host lifetime
    /// discriminator. A task gone between the two reads (or before them)
    /// refuses `Gone…` with the tgid preserved; denial refuses typed.
    pub fn read_pid(&self, tgid: u32) -> Result<PidEntry, HostReadError> {
        let base = self.proc_root.join(tgid.to_string());
        let cgroup_text = match read_bounded(&base.join("cgroup")) {
            Ok(text) => text,
            Err(HostReadError::Unsupported) => return Err(HostReadError::GonePid { tgid }),
            Err(other) => {
                return Err(map_pid_error(other, tgid));
            }
        };
        let hint = parse_cgroup_v2_line(&cgroup_text).ok_or(HostReadError::Invalid)?;
        if hint.is_empty() {
            return Err(HostReadError::Invalid);
        }
        let stat_text = match read_bounded(&base.join("stat")) {
            Ok(text) => text,
            Err(HostReadError::Unsupported) => return Err(HostReadError::GonePid { tgid }),
            Err(other) => return Err(map_pid_error(other, tgid)),
        };
        let start_ticks = parse_stat_starttime(&stat_text).ok_or(HostReadError::Invalid)?;
        Ok(PidEntry {
            tgid,
            hint: hint.to_string(),
            start_ticks,
        })
    }

    /// Confine-resolve a `/proc` cgroup hint under the cgroup root and
    /// return the live object's (dev, ino). Never follows symlinks, never
    /// leaves the root device, never joins relative/escaping hints.
    pub fn resolve_hint(
        &self,
        hint: &str,
        counters: &mut HelperCounters,
    ) -> Result<(u64, u64), HostReadError> {
        let components = check_hint_lexical(hint).ok_or(HostReadError::NotHostPath)?;
        if components.len() > MAX_HINT_COMPONENTS {
            return Err(HostReadError::BudgetExceeded);
        }
        let root_meta = std::fs::metadata(&self.cgroup_root).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                counters.inc_denied();
            }
            HostReadError::Unsupported
        })?;
        let root_dev = root_meta.dev();
        let mut current = self.cgroup_root.clone();
        for component in hint.split('/').filter(|c| !c.is_empty()) {
            current.push(component);
            let meta = std::fs::symlink_metadata(&current).map_err(|e| {
                let err = host_io_error(e, false);
                counters.note_host_error(&err);
                err
            })?;
            if meta.file_type().is_symlink() {
                counters.note_host_error(&HostReadError::SymlinkRefused);
                return Err(HostReadError::SymlinkRefused);
            }
            if !meta.is_dir() {
                return Err(HostReadError::NotHostPath);
            }
            if meta.dev() != root_dev {
                counters.note_host_error(&HostReadError::NotHostPath);
                return Err(HostReadError::NotHostPath);
            }
        }
        let meta = std::fs::metadata(&current).map_err(|e| {
            let err = host_io_error(e, false);
            counters.note_host_error(&err);
            err
        })?;
        if meta.dev() != root_dev {
            counters.note_host_error(&HostReadError::NotHostPath);
            return Err(HostReadError::NotHostPath);
        }
        Ok((meta.dev(), meta.ino()))
    }

    /// Bind several captured cgroup ids in ONE confined inode walk (the
    /// request's whole uncached set; never one traversal per event). Each
    /// match is confirmed by re-stat (replacement refuses
    /// [`HostReadError::ReuseDetected`]). Returns the bound objects plus
    /// whether any denial made coverage incomplete (unfound targets are
    /// then unknown, not absent). Symlinks are refused, never followed;
    /// the walk never leaves the root device.
    pub fn find_cgroups(
        &self,
        targets: &[u64],
        counters: &mut HelperCounters,
    ) -> Result<(std::collections::HashMap<u64, CgroupObject>, bool), HostReadError> {
        use std::collections::{HashMap, HashSet};
        let root_meta =
            std::fs::metadata(&self.cgroup_root).map_err(|_| HostReadError::Unsupported)?;
        let root_dev = root_meta.dev();
        let wanted: HashSet<u64> = targets.iter().copied().collect();
        let mut found: HashMap<u64, CgroupObject> = HashMap::new();
        // The root itself is a bindable object (host root cgroup).
        if let Some(object) = check_candidate(&self.cgroup_root, root_dev, &wanted, counters)? {
            found.insert(object.cgroup, object);
        }
        let denied_before = counters.denied;
        let mut visited: usize = 0;
        let mut stack = vec![self.cgroup_root.clone()];
        while let Some(dir) = stack.pop() {
            if found.len() == wanted.len() {
                break;
            }
            visited += 1;
            if visited > MAX_CGROUP_SCAN_DIRS {
                counters.inc_scan_budget_trips();
                return Err(HostReadError::BudgetExceeded);
            }
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    counters.note_host_error(&HostReadError::GoneDuringScan);
                    continue;
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    counters.inc_denied();
                    continue;
                }
                Err(_) => {
                    counters.note_host_error(&HostReadError::Invalid);
                    continue;
                }
            };
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        counters.note_host_error(&HostReadError::GoneDuringScan);
                        continue;
                    }
                    Err(_) => {
                        counters.note_host_error(&HostReadError::Invalid);
                        continue;
                    }
                };
                let meta = match std::fs::symlink_metadata(entry.path()) {
                    Ok(meta) => meta,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        counters.note_host_error(&HostReadError::GoneDuringScan);
                        continue;
                    }
                    Err(_) => {
                        counters.note_host_error(&HostReadError::Invalid);
                        continue;
                    }
                };
                if meta.file_type().is_symlink() {
                    counters.note_host_error(&HostReadError::SymlinkRefused);
                    continue;
                }
                if !meta.is_dir() {
                    continue;
                }
                if meta.dev() != root_dev {
                    counters.note_host_error(&HostReadError::NotHostPath);
                    continue;
                }
                if wanted.contains(&meta.ino()) && !found.contains_key(&meta.ino()) {
                    // Confirm stability: re-stat before binding.
                    let confirm = std::fs::metadata(entry.path()).map_err(|e| {
                        let err = host_io_error(e, false);
                        counters.note_host_error(&err);
                        err
                    })?;
                    if !confirm_stable((meta.dev(), meta.ino()), (confirm.dev(), confirm.ino())) {
                        counters.note_host_error(&HostReadError::ReuseDetected);
                        return Err(HostReadError::ReuseDetected);
                    }
                    found.insert(
                        meta.ino(),
                        CgroupObject {
                            cgroup: meta.ino(),
                            dev: confirm.dev(),
                            ino: confirm.ino(),
                        },
                    );
                    // Still descend: wanted inodes may nest.
                }
                stack.push(entry.path());
            }
        }
        Ok((found, counters.denied != denied_before))
    }
}

/// Check one directory (used for the scan root) as a bind candidate.
fn check_candidate(
    dir: &Path,
    root_dev: u64,
    wanted: &std::collections::HashSet<u64>,
    counters: &mut HelperCounters,
) -> Result<Option<CgroupObject>, HostReadError> {
    let meta = std::fs::metadata(dir).map_err(|e| {
        let err = host_io_error(e, false);
        counters.note_host_error(&err);
        err
    })?;
    if meta.dev() == root_dev && wanted.contains(&meta.ino()) {
        return Ok(Some(CgroupObject {
            cgroup: meta.ino(),
            dev: meta.dev(),
            ino: meta.ino(),
        }));
    }
    Ok(None)
}

/// Read a small host file bounded; missing files map to `Unsupported` so
/// pid readers can reinterpret them as gone.
fn read_bounded(path: &Path) -> Result<String, HostReadError> {
    let bytes = std::fs::read(path).map_err(|e| host_io_error(e, true))?;
    if bytes.len() > MAX_PID_FILE_BYTES {
        return Err(HostReadError::Invalid);
    }
    String::from_utf8(bytes).map_err(|_| HostReadError::Invalid)
}

/// Map an I/O error to a typed host error (no path echo). `missing_ok`
/// distinguishes "view absent" (roots) from "object gone" (walk).
fn host_io_error(error: std::io::Error, missing_ok: bool) -> HostReadError {
    match error.kind() {
        std::io::ErrorKind::NotFound if missing_ok => HostReadError::Unsupported,
        std::io::ErrorKind::NotFound => HostReadError::GoneDuringScan,
        std::io::ErrorKind::PermissionDenied => HostReadError::DeniedCgroup { cgroup: 0 },
        _ => HostReadError::Invalid,
    }
}

/// Reinterpret a generic host error for the pid it was read for.
fn map_pid_error(error: HostReadError, tgid: u32) -> HostReadError {
    match error {
        HostReadError::DeniedCgroup { .. } => HostReadError::DeniedPid { tgid },
        other => other,
    }
}

/// Lexical gate for `/proc` cgroup hints: absolute, no empty/`.`/`..`
/// components, no NUL. Returns the components on success.
fn check_hint_lexical(hint: &str) -> Option<Vec<&str>> {
    if !hint.starts_with('/') || hint.bytes().any(|b| b == 0) {
        return None;
    }
    let mut components = Vec::new();
    for component in hint.split('/').filter(|c| !c.is_empty()) {
        if component == "." || component == ".." {
            return None;
        }
        components.push(component);
    }
    Some(components)
}

/// Extract the cgroup v2 `0::` path (exactly one required; v1-only views
/// yield `None` and refuse upstream as unusable-for-M1).
fn parse_cgroup_v2_line(text: &str) -> Option<&str> {
    let mut found = None;
    for line in text.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            if found.is_some() {
                return None;
            }
            found = Some(path);
        }
    }
    found
}

/// Parse `/proc/<tgid>/stat` field 22 (starttime, boot clock ticks).
/// Splits after the LAST `)` so spaces/parens in comm cannot shift fields.
fn parse_stat_starttime(text: &str) -> Option<u64> {
    let after_comm = text.rsplit(')').next()?.trim_start();
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // state=3 is fields[0], so starttime=22 is fields[19].
    fields.get(19)?.parse().ok()
}

/// Parse `/proc/uptime` into boot-relative nanoseconds (saturating).
fn parse_uptime_ns(text: &str) -> Option<u64> {
    let first = text.split_whitespace().next()?;
    let (secs_text, frac_text) = match first.split_once('.') {
        Some((s, f)) => (s, f),
        None => (first, ""),
    };
    let secs: u64 = if secs_text.is_empty() {
        0
    } else {
        secs_text.parse().ok()?
    };
    let mut frac_ns: u64 = 0;
    for (i, digit) in frac_text.bytes().take(9).enumerate() {
        if !digit.is_ascii_digit() {
            return None;
        }
        let place = 10u64.pow(8 - i as u32);
        frac_ns += u64::from(digit - b'0') * place;
    }
    if frac_text.len() > 9 && !frac_text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(secs.saturating_mul(1_000_000_000).saturating_add(frac_ns))
}

/// Stability confirm: the object re-stat must show the same device and
/// inode (replacement under us refuses rather than binding a stranger).
#[must_use]
pub const fn confirm_stable(first: (u64, u64), second: (u64, u64)) -> bool {
    first.0 == second.0 && first.1 == second.1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_line_parsing_is_exact() {
        assert_eq!(
            parse_cgroup_v2_line("0::/kubepods/a\n"),
            Some("/kubepods/a")
        );
        assert_eq!(parse_cgroup_v2_line("12::/x\n0::/\n"), Some("/"));
        // v1-only view: no usable line.
        assert_eq!(parse_cgroup_v2_line("2:cpu:/x\n1:name=y:/z\n"), None);
        // Duplicated hierarchy lines refuse.
        assert_eq!(parse_cgroup_v2_line("0::/a\n0::/b\n"), None);
        assert_eq!(parse_cgroup_v2_line(""), None);
    }

    #[test]
    fn stat_starttime_survives_hostile_comm() {
        let plain = "4242 (fixture) R 1 1 1 0 -1 4194304 10 0 0 0 5 5 0 0 20 0 2 0 777888 0 0\n";
        assert_eq!(parse_stat_starttime(plain), Some(777888));
        let hostile =
            "4242 (my (weird) proc) R 1 1 1 0 -1 4194304 10 0 0 0 5 5 0 0 20 0 2 0 123 0 0\n";
        assert_eq!(parse_stat_starttime(hostile), Some(123));
        assert_eq!(parse_stat_starttime("4242 (short) R 1\n"), None);
        assert_eq!(parse_stat_starttime("no parens here\n"), None);
    }

    #[test]
    fn uptime_parses_to_nanoseconds() {
        assert_eq!(parse_uptime_ns("100.00 200.00\n"), Some(100_000_000_000));
        assert_eq!(parse_uptime_ns("0.50 0\n"), Some(500_000_000));
        assert_eq!(parse_uptime_ns("1.123456789 0\n"), Some(1_123_456_789));
        assert_eq!(parse_uptime_ns("42 0\n"), Some(42_000_000_000));
        assert_eq!(parse_uptime_ns(""), None);
        assert_eq!(parse_uptime_ns("soon 0\n"), None);
        assert_eq!(parse_uptime_ns("1.2x 0\n"), None);
    }

    #[test]
    fn hint_lexical_gate() {
        assert!(check_hint_lexical("/kubepods/a").is_some());
        assert!(check_hint_lexical("/").is_some());
        assert!(check_hint_lexical("relative/path").is_none());
        assert!(check_hint_lexical("").is_none());
        assert!(check_hint_lexical("/../escape").is_none());
        assert!(check_hint_lexical("/a/./b").is_none());
        assert!(check_hint_lexical("/a\0/b").is_none());
    }

    #[test]
    fn stability_confirm_is_exact() {
        assert!(confirm_stable((8, 100), (8, 100)));
        assert!(!confirm_stable((8, 100), (8, 101)));
        assert!(!confirm_stable((8, 100), (9, 100)));
    }

    fn scratch(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "kwh-host-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    /// A hint into a concurrently deleted subtree refuses
    /// `GoneDuringScan` (typed, counted) instead of resolving half a path.
    #[test]
    fn deleted_subtree_refuses_gone_during_scan() {
        let dir = scratch("deleted");
        let root = dir.join("cgroup");
        std::fs::create_dir_all(&root).expect("mkdir");
        let view = HostView::new(&dir.join("proc"), &root);
        let mut counters = HelperCounters::new();
        assert_eq!(
            view.resolve_hint("/vanished/child", &mut counters),
            Err(HostReadError::GoneDuringScan)
        );
        assert_eq!(counters.gone_during_scan, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A process whose stat disappears after its cgroup file read (gone
    /// between the two phases) refuses `GonePid` with the tgid preserved.
    #[test]
    fn pid_vanishing_between_phases_refuses_gone() {
        let dir = scratch("phases");
        let pid = dir.join("proc/4242");
        std::fs::create_dir_all(&pid).expect("mkdir");
        std::fs::write(pid.join("cgroup"), "0::/grp\n").expect("write");
        let view = HostView::new(&dir.join("proc"), &dir.join("cgroup"));
        assert_eq!(
            view.read_pid(4242),
            Err(HostReadError::GonePid { tgid: 4242 })
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn error_kinds_and_displays_carry_no_paths() {
        let errors = [
            HostReadError::GonePid { tgid: 7 },
            HostReadError::GoneDuringScan,
            HostReadError::DeniedPid { tgid: 7 },
            HostReadError::DeniedCgroup { cgroup: 9 },
            HostReadError::NotHostPath,
            HostReadError::SymlinkRefused,
            HostReadError::ReuseDetected,
            HostReadError::BudgetExceeded,
            HostReadError::Unsupported,
            HostReadError::Invalid,
        ];
        for error in errors {
            let text = error.to_string();
            assert!(!text.contains('/'), "error must carry no path: {text}");
            assert!(!error.kind().is_empty());
        }
        assert_eq!(HostReadError::GonePid { tgid: 1 }.kind(), "gone");
        assert_eq!(HostReadError::DeniedCgroup { cgroup: 1 }.kind(), "denied");
    }
}
