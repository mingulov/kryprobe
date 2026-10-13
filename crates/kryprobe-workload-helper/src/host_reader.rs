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
//!   [`MAX_SCAN_ENTRIES_EXAMINED`], [`MAX_SCAN_QUEUED_DIRS`],
//!   [`MAX_SCAN_LISTING`], [`MAX_PID_FILE_BYTES`]) plus the request
//!   deadline predicate during the walk; all errors are typed with
//!   numeric ids only — paths and file bytes never appear in
//!   diagnostics.
//! - Deletion or replacement mid-traversal refuses typed (`Gone…`,
//!   `ReuseDetected`) with the captured ids preserved; permission denial
//!   refuses typed (`Denied…`), never silently.

use crate::cache::HelperCounters;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Filesystem seam for the cgroup inode scan: production walks the live
/// tree ([`RealFs`]); tests inject counting walkers to prove work bounds.
/// Directory listings are sorted so scans iterate deterministically.
pub trait ScanFs {
    /// List a directory's children in sorted order, preserving per-entry
    /// errors (a racy child refuses typed, never silently dropped).
    /// Consults `deadline` while collecting (every 64 entries) and once
    /// more before sorting; an expired deadline refuses with an
    /// [`std::io::ErrorKind::TimedOut`] I/O error (mapped to
    /// [`HostReadError::DeadlineExceeded`] at the call site) instead of
    /// collecting or sorting further.
    fn read_dir_sorted(
        &self,
        dir: &Path,
        deadline: &dyn Fn() -> bool,
    ) -> std::io::Result<Vec<std::io::Result<PathBuf>>>;

    /// Metadata without following a trailing symlink.
    fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata>;

    /// Metadata following symlinks (stability re-stats only).
    fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata>;
}

/// Production walker: the live `std::fs` tree, listings sorted for
/// deterministic iteration.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealFs;

impl ScanFs for RealFs {
    fn read_dir_sorted(
        &self,
        dir: &Path,
        deadline: &dyn Fn() -> bool,
    ) -> std::io::Result<Vec<std::io::Result<PathBuf>>> {
        let mut entries: Vec<std::io::Result<PathBuf>> = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            if entries.len() >= MAX_SCAN_LISTING {
                // Pathological listing: refuse typed (mapped to
                // `BudgetExceeded` at the call site) rather than growing
                // the collection without bound or truncating silently.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::QuotaExceeded,
                    "directory listing exceeds scan bound",
                ));
            }
            entries.push(entry.map(|e| e.path()));
            // Wide listings re-check the deadline as they collect, so an
            // expired deadline stops collection within one slice instead
            // of sweeping every child before any gate runs.
            if entries
                .len()
                .is_multiple_of(COLLECTION_DEADLINE_CHECK_EVERY_ENTRIES)
                && deadline()
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "directory listing collection crossed the deadline",
                ));
            }
        }
        // Refuse before sorting: an expired deadline skips the sort
        // entirely rather than ordering a listing that will be refused.
        if deadline() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "directory listing collection crossed the deadline",
            ));
        }
        entries.sort_by(|a, b| match (a, b) {
            (Ok(left), Ok(right)) => left.cmp(right),
            (Ok(_), Err(_)) => std::cmp::Ordering::Less,
            (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
            (Err(_), Err(_)) => std::cmp::Ordering::Equal,
        });
        Ok(entries)
    }

    fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        std::fs::symlink_metadata(path)
    }

    fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        std::fs::metadata(path)
    }
}

/// Helper-local pin: maximum cgroup directories visited in one inode
/// scan. Exhaustion refuses [`HostReadError::BudgetExceeded`].
pub const MAX_CGROUP_SCAN_DIRS: usize = 4096;

/// Helper-local pin: maximum child entries examined in one inode scan,
/// across all visited directories. Charged before any metadata work on
/// the entry; exhaustion refuses [`HostReadError::BudgetExceeded`].
/// Independent of the visited-directory count: a single wide directory
/// trips this bound while barely moving the visited count.
pub const MAX_SCAN_ENTRIES_EXAMINED: usize = 4096;

/// Helper-local pin: maximum directories queued for descent in one inode
/// scan. Charged before each push; exhaustion refuses
/// [`HostReadError::BudgetExceeded`]. Independent of the visited count:
/// the pending set never grows past this.
pub const MAX_SCAN_QUEUED_DIRS: usize = 4096;

/// Helper-local pin: maximum children collected from one directory
/// listing. A listing past this refuses [`HostReadError::BudgetExceeded`]
/// before examination (no silent truncation: skipped children must never
/// read as absent). Far above the charge bounds so ordinary trees list
/// fully and deterministically.
pub const MAX_SCAN_LISTING: usize = 65_536;

/// Entries examined between in-scan deadline checks (the per-directory
/// check plus this cadence bound post-deadline work to one slice).
const DEADLINE_CHECK_EVERY_ENTRIES: u64 = 256;

/// Entries collected between in-collection deadline checks inside
/// [`ScanFs::read_dir_sorted`] (plus one check before sorting, so the
/// sort never runs post-deadline). Tighter than the examination
/// cadence, so a wide listing stops well within one examination slice
/// past expiry.
const COLLECTION_DEADLINE_CHECK_EVERY_ENTRIES: usize = 64;

/// Per-scan work budget: entries examined plus directories queued, each
/// capped (see [`MAX_SCAN_ENTRIES_EXAMINED`], [`MAX_SCAN_QUEUED_DIRS`]).
/// Charges happen BEFORE the work they pay for (metadata stat, queue
/// push), so a refusal means the work never ran. Counters saturate —
/// they never wrap past the bound check. Internal to one
/// [`HostView::find_cgroups`] call; never serialized (counter DTO fields
/// are F07 scope).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanBudget {
    entries_examined: u64,
    queued_dirs: u64,
}

impl ScanBudget {
    /// Empty budget for one scan.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries_examined: 0,
            queued_dirs: 0,
        }
    }

    /// Entries charged so far (saturating, never wraps).
    #[must_use]
    pub const fn entries_examined(&self) -> u64 {
        self.entries_examined
    }

    /// Directories queued so far (saturating, never wraps). Observed
    /// by tests; production enforces the bound through the charges.
    #[cfg(test)]
    #[must_use]
    pub const fn queued_dirs(&self) -> u64 {
        self.queued_dirs
    }

    /// Charge one examined child entry BEFORE any metadata work on it.
    /// Refuses [`HostReadError::BudgetExceeded`] past
    /// [`MAX_SCAN_ENTRIES_EXAMINED`]; exactly at the bound is allowed.
    fn charge_entry(&mut self) -> Result<(), HostReadError> {
        if self.entries_examined >= MAX_SCAN_ENTRIES_EXAMINED as u64 {
            return Err(HostReadError::BudgetExceeded);
        }
        self.entries_examined = self.entries_examined.saturating_add(1);
        Ok(())
    }

    /// Charge one queued directory BEFORE pushing it. Refuses
    /// [`HostReadError::BudgetExceeded`] past [`MAX_SCAN_QUEUED_DIRS`];
    /// exactly at the bound is allowed. (The walked root itself is the
    /// seed, never a queued child.)
    fn charge_enqueue(&mut self) -> Result<(), HostReadError> {
        if self.queued_dirs >= MAX_SCAN_QUEUED_DIRS as u64 {
            return Err(HostReadError::BudgetExceeded);
        }
        self.queued_dirs = self.queued_dirs.saturating_add(1);
        Ok(())
    }
}

impl Default for ScanBudget {
    fn default() -> Self {
        Self::new()
    }
}

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
    /// The request deadline crossed mid-scan (explicit trip/refusal path;
    /// checked before the walk, per directory, during listing collection
    /// and long enumerations, and before confirming candidates).
    DeadlineExceeded,
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
            Self::DeadlineExceeded => "deadline_exceeded",
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
            Self::DeadlineExceeded => write!(f, "resolution deadline exceeded"),
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
    ///
    /// The walk is bounded three ways, checked in this order: the request
    /// `deadline` predicate (before the walk, per directory, during
    /// listing collection and long enumerations, and before confirming
    /// candidates — trips refuse typed [`HostReadError::DeadlineExceeded`]),
    /// the per-scan
    /// [`ScanBudget`] (entries examined and directories queued, charged
    /// before the work — trips refuse [`HostReadError::BudgetExceeded`]),
    /// and the visited-directory backstop ([`MAX_CGROUP_SCAN_DIRS`]).
    /// Finding every target stops the walk immediately, even
    /// mid-directory. All refusals are typed with numeric ids only.
    ///
    /// These gates are cooperative: each check runs between syscalls, and
    /// one `read_dir`/stat runs to completion once issued. The parent
    /// launcher's independent 30 s kill backstop stays necessary and is
    /// retained for syscalls that stall past every helper-side check.
    pub fn find_cgroups(
        &self,
        targets: &[u64],
        counters: &mut HelperCounters,
        fs: &dyn ScanFs,
        budget: &mut ScanBudget,
        deadline: &dyn Fn() -> bool,
    ) -> Result<(std::collections::HashMap<u64, CgroupObject>, bool), HostReadError> {
        use std::collections::{HashMap, HashSet};
        if deadline() {
            let err = HostReadError::DeadlineExceeded;
            counters.note_host_error(&err);
            return Err(err);
        }
        let root_meta = fs
            .metadata(&self.cgroup_root)
            .map_err(|_| HostReadError::Unsupported)?;
        let root_dev = root_meta.dev();
        let wanted: HashSet<u64> = targets.iter().copied().collect();
        let mut found: HashMap<u64, CgroupObject> = HashMap::new();
        // The root itself is a bindable object (host root cgroup).
        if let Some(object) = check_candidate(&self.cgroup_root, root_dev, &wanted, counters, fs)? {
            found.insert(object.cgroup, object);
        }
        let denied_before = counters.denied;
        let mut visited: usize = 0;
        let mut stack = vec![self.cgroup_root.clone()];
        'scan: while let Some(dir) = stack.pop() {
            if found.len() == wanted.len() {
                break;
            }
            visited += 1;
            if visited > MAX_CGROUP_SCAN_DIRS {
                counters.inc_scan_budget_trips();
                return Err(HostReadError::BudgetExceeded);
            }
            if deadline() {
                let err = HostReadError::DeadlineExceeded;
                counters.note_host_error(&err);
                return Err(err);
            }
            let entries = match fs.read_dir_sorted(&dir, deadline) {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    counters.note_host_error(&HostReadError::GoneDuringScan);
                    continue;
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    counters.inc_denied();
                    continue;
                }
                Err(e) if e.kind() == std::io::ErrorKind::QuotaExceeded => {
                    // Pathological listing past MAX_SCAN_LISTING: a
                    // budget refusal, never a silent truncation.
                    counters.note_host_error(&HostReadError::BudgetExceeded);
                    return Err(HostReadError::BudgetExceeded);
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    // Collection crossed the deadline mid-listing: a
                    // deadline refusal, never a silent truncation.
                    // (Local directory iteration never times out on its
                    // own; this kind only signals the collection gate.)
                    counters.note_host_error(&HostReadError::DeadlineExceeded);
                    return Err(HostReadError::DeadlineExceeded);
                }
                Err(_) => {
                    counters.note_host_error(&HostReadError::Invalid);
                    continue;
                }
            };
            for entry in entries {
                // Charge before any metadata work on this child.
                if let Err(err) = budget.charge_entry() {
                    counters.note_host_error(&err);
                    return Err(err);
                }
                // Long enumerations re-check the deadline as they go, so
                // a single wide directory cannot outrun it for the whole
                // slice.
                if budget
                    .entries_examined()
                    .is_multiple_of(DEADLINE_CHECK_EVERY_ENTRIES)
                    && deadline()
                {
                    let err = HostReadError::DeadlineExceeded;
                    counters.note_host_error(&err);
                    return Err(err);
                }
                let path = match entry {
                    Ok(path) => path,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        counters.note_host_error(&HostReadError::GoneDuringScan);
                        continue;
                    }
                    Err(_) => {
                        counters.note_host_error(&HostReadError::Invalid);
                        continue;
                    }
                };
                let meta = match fs.symlink_metadata(&path) {
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
                    if deadline() {
                        let err = HostReadError::DeadlineExceeded;
                        counters.note_host_error(&err);
                        return Err(err);
                    }
                    // Confirm stability: re-stat before binding.
                    let confirm = fs.metadata(&path).map_err(|e| {
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
                    if found.len() == wanted.len() {
                        // Every target bound: stop now, even mid-directory.
                        break 'scan;
                    }
                    // Still descend: wanted inodes may nest.
                }
                // Charge before queueing.
                if let Err(err) = budget.charge_enqueue() {
                    counters.note_host_error(&err);
                    return Err(err);
                }
                stack.push(path);
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
    fs: &dyn ScanFs,
) -> Result<Option<CgroupObject>, HostReadError> {
    let meta = fs.metadata(dir).map_err(|e| {
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

    /// Counting walker: delegates to the live tree while recording every
    /// read/stat operation, so tests prove work bounds on real syscalls.
    struct CountingFs {
        inner: RealFs,
        read_dirs: std::cell::Cell<usize>,
        symlink_stats: std::cell::Cell<usize>,
        stats: std::cell::Cell<usize>,
    }

    impl CountingFs {
        fn new() -> Self {
            Self {
                inner: RealFs,
                read_dirs: std::cell::Cell::new(0),
                symlink_stats: std::cell::Cell::new(0),
                stats: std::cell::Cell::new(0),
            }
        }

        fn bump(cell: &std::cell::Cell<usize>) {
            cell.set(cell.get().saturating_add(1));
        }
    }

    impl ScanFs for CountingFs {
        fn read_dir_sorted(
            &self,
            dir: &Path,
            deadline: &dyn Fn() -> bool,
        ) -> std::io::Result<Vec<std::io::Result<PathBuf>>> {
            Self::bump(&self.read_dirs);
            self.inner.read_dir_sorted(dir, deadline)
        }

        fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
            Self::bump(&self.symlink_stats);
            self.inner.symlink_metadata(path)
        }

        fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
            Self::bump(&self.stats);
            self.inner.metadata(path)
        }
    }

    /// One counted scan: the outcome, the real (read_dir, symlink_stat,
    /// stat) operation counts, and the charged (entries, queued) budget
    /// totals.
    type CountedScan = (
        Result<(std::collections::HashMap<u64, CgroupObject>, bool), HostReadError>,
        (usize, usize, usize),
        (u64, u64),
    );

    /// Run one scan under a counting walker with a fresh budget and a
    /// live deadline.
    fn scan(
        view: &HostView,
        targets: &[u64],
        counters: &mut HelperCounters,
        fs: &CountingFs,
    ) -> CountedScan {
        let mut budget = ScanBudget::new();
        let outcome = view.find_cgroups(targets, counters, fs, &mut budget, &|| false);
        let ops = (fs.read_dirs.get(), fs.symlink_stats.get(), fs.stats.get());
        let charged = (budget.entries_examined(), budget.queued_dirs());
        (outcome, ops, charged)
    }

    fn mkdir(path: &Path) {
        std::fs::create_dir_all(path).expect("mkdir");
    }

    fn touch(path: &Path) {
        std::fs::write(path, b"x").expect("write");
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

    /// PRIV01: child enumeration and pending descent are bounded
    /// independently of the visited-directory count. A wide tree (5000
    /// readable children, missing target, deterministic sorted iteration)
    /// refuses typed [`HostReadError::BudgetExceeded`] with real read/stat
    /// work capped; a wanted-first target stops the scan early instead of
    /// sweeping the whole tree.
    #[test]
    fn wide_scan_bounds_entries_and_pending() {
        // Case 1: 5000 plain files. No directory is ever queued or
        // visited, so a visited-only budget never trips — yet every child
        // costs a stat. The entries bound must refuse before that work
        // runs away.
        let dir = scratch("wide-files");
        let root = dir.join("cgroup");
        mkdir(&root);
        for i in 0..5000 {
            touch(&root.join(format!("file-{i:05}")));
        }
        let view = HostView::new(&dir.join("proc"), &root);
        let mut counters = HelperCounters::new();
        let (outcome, (read_dirs, symlink_stats, _), (entries, queued)) =
            scan(&view, &[u64::MAX - 7], &mut counters, &CountingFs::new());
        assert_eq!(outcome, Err(HostReadError::BudgetExceeded));
        assert_eq!(counters.scan_budget_trips, 1);
        assert!(
            symlink_stats <= MAX_SCAN_ENTRIES_EXAMINED,
            "stat work must stop at the entries bound, did {symlink_stats}"
        );
        assert_eq!(read_dirs, 1, "one directory listed, did {read_dirs}");
        assert_eq!((entries, queued), (4096, 0), "exact charges, no overflow");
        let _ = std::fs::remove_dir_all(&dir);

        // Case 2: 5000 readable child directories, missing target. The
        // queue must not grow past its bound (no pending-path overflow)
        // and charged work must stop — a handful of operations, not a
        // thousands-deep stack drained one pop at a time.
        let dir = scratch("wide-dirs");
        let root = dir.join("cgroup");
        mkdir(&root);
        for i in 0..5000 {
            mkdir(&root.join(format!("child-{i:05}")));
        }
        let view = HostView::new(&dir.join("proc"), &root);
        let mut counters = HelperCounters::new();
        let (outcome, (read_dirs, symlink_stats, _), (entries, queued)) =
            scan(&view, &[u64::MAX - 7], &mut counters, &CountingFs::new());
        assert_eq!(outcome, Err(HostReadError::BudgetExceeded));
        assert_eq!(counters.scan_budget_trips, 1);
        assert!(
            symlink_stats <= MAX_SCAN_ENTRIES_EXAMINED,
            "stat work must stop at the entries bound, did {symlink_stats}"
        );
        assert!(
            read_dirs <= 2,
            "descent must stop at the queue bound, listed {read_dirs} dirs"
        );
        assert_eq!(
            (entries, queued),
            (4096, 4096),
            "exact charges, no overflow"
        );
        let _ = std::fs::remove_dir_all(&dir);

        // Case 3: wanted-first early stop. The single target sorts before
        // 5000 siblings; finding it must end the scan, not merely skip
        // the remaining pops.
        let dir = scratch("wide-first");
        let root = dir.join("cgroup");
        mkdir(&root);
        for i in 0..5000 {
            mkdir(&root.join(format!("child-{i:05}")));
        }
        let wanted_path = root.join("aaa-wanted");
        mkdir(&wanted_path);
        let wanted_ino = std::fs::metadata(&wanted_path).expect("stat").ino();
        let view = HostView::new(&dir.join("proc"), &root);
        let mut counters = HelperCounters::new();
        let (outcome, (read_dirs, symlink_stats, _), (entries, queued)) =
            scan(&view, &[wanted_ino], &mut counters, &CountingFs::new());
        let (found, denied) = outcome.expect("wanted-first scan binds");
        assert!(!denied);
        assert_eq!(found.len(), 1);
        assert_eq!(found[&wanted_ino].ino, wanted_ino);
        assert_eq!(counters.scan_budget_trips, 0);
        assert!(
            symlink_stats <= 4,
            "early stop must skip the siblings, statted {symlink_stats}"
        );
        assert_eq!(read_dirs, 1, "one directory listed, did {read_dirs}");
        assert_eq!((entries, queued), (1, 0), "one charge, then stop");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Exact-boundary positive control: 4096 children with the target
    /// sorting last are all examined and queued without tripping (the
    /// bounds refuse only past 4096), and the deep-tree control binds a
    /// target nested 300 levels down with small bounded work.
    #[test]
    fn scan_boundary_and_depth_controls() {
        // Exactly at the bound: allowed.
        let dir = scratch("exact-bound");
        let root = dir.join("cgroup");
        mkdir(&root);
        for i in 0..4095 {
            mkdir(&root.join(format!("child-{i:05}")));
        }
        let wanted_path = root.join("zzz-wanted");
        mkdir(&wanted_path);
        let wanted_ino = std::fs::metadata(&wanted_path).expect("stat").ino();
        let view = HostView::new(&dir.join("proc"), &root);
        let mut counters = HelperCounters::new();
        let (outcome, (read_dirs, symlink_stats, _), (entries, queued)) =
            scan(&view, &[wanted_ino], &mut counters, &CountingFs::new());
        let (found, denied) = outcome.expect("exact-bound scan binds");
        assert!(!denied);
        assert_eq!(found.len(), 1);
        assert_eq!(found[&wanted_ino].ino, wanted_ino);
        assert_eq!(counters.scan_budget_trips, 0);
        assert_eq!(symlink_stats, 4096, "every child examined once");
        assert_eq!(read_dirs, 1);
        assert_eq!(
            (entries, queued),
            (4096, 4095),
            "exact charges, no overflow"
        );
        let _ = std::fs::remove_dir_all(&dir);

        // Deep narrow tree: bounded work, no trip.
        let dir = scratch("deep-tree");
        let root = dir.join("cgroup");
        let mut deep = root.clone();
        for level in 0..300 {
            deep = deep.join(format!("l{level:03}"));
        }
        mkdir(&deep);
        let wanted_ino = std::fs::metadata(&deep).expect("stat").ino();
        let view = HostView::new(&dir.join("proc"), &root);
        let mut counters = HelperCounters::new();
        let (outcome, (read_dirs, symlink_stats, _), (entries, queued)) =
            scan(&view, &[wanted_ino], &mut counters, &CountingFs::new());
        let (found, denied) = outcome.expect("deep scan binds");
        assert!(!denied);
        assert_eq!(found.len(), 1);
        assert_eq!(found[&wanted_ino].ino, wanted_ino);
        assert_eq!(counters.scan_budget_trips, 0);
        assert_eq!(symlink_stats, 300, "one stat per level");
        assert_eq!(read_dirs, 300, "one listing per level");
        assert_eq!((entries, queued), (300, 299), "exact charges, no overflow");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// PRIV02 at the walk: the deadline predicate is honored before any
    /// metadata work and during the walk, refusing typed
    /// [`HostReadError::DeadlineExceeded`] (deadline counter exactly 1,
    /// no path strings anywhere in the refusal).
    #[test]
    fn scan_deadline_trip_refuses_typed() {
        let dir = scratch("deadline");
        let root = dir.join("cgroup");
        mkdir(&root.join("child"));
        let view = HostView::new(&dir.join("proc"), &root);

        // Tripped before the walk: nothing is read.
        let mut counters = HelperCounters::new();
        let fs = CountingFs::new();
        let mut budget = ScanBudget::new();
        let outcome = view.find_cgroups(&[1], &mut counters, &fs, &mut budget, &|| true);
        assert_eq!(outcome, Err(HostReadError::DeadlineExceeded));
        assert_eq!(counters.deadline_trips, 1);
        assert_eq!(counters.scan_budget_trips, 0);
        assert_eq!(fs.read_dirs.get(), 0, "no directory listed");
        assert_eq!(fs.symlink_stats.get(), 0, "nothing statted");
        assert_eq!(budget.entries_examined(), 0);
        assert_eq!(budget.queued_dirs(), 0);

        // Tripped during the walk (third predicate read): partial work,
        // then the typed refusal.
        let mut counters = HelperCounters::new();
        let fs = CountingFs::new();
        let mut budget = ScanBudget::new();
        let reads = std::cell::Cell::new(0u32);
        let outcome = view.find_cgroups(&[u64::MAX - 3], &mut counters, &fs, &mut budget, &|| {
            reads.set(reads.get() + 1);
            reads.get() >= 3
        });
        assert_eq!(outcome, Err(HostReadError::DeadlineExceeded));
        assert_eq!(counters.deadline_trips, 1);
        assert_eq!(counters.scan_budget_trips, 0);

        // The refusal carries no paths.
        let text = HostReadError::DeadlineExceeded.to_string();
        assert!(!text.contains('/'), "refusal must carry no path: {text}");
        assert_eq!(HostReadError::DeadlineExceeded.kind(), "deadline_exceeded");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pathological single listing (past [`MAX_SCAN_LISTING`]) refuses
    /// typed [`HostReadError::BudgetExceeded`] instead of growing the
    /// collection without bound or truncating silently (skipped children
    /// must never read as absent).
    #[test]
    fn scan_pathological_listing_refuses_budget() {
        struct CappedFs;
        impl ScanFs for CappedFs {
            fn read_dir_sorted(
                &self,
                _dir: &Path,
                deadline: &dyn Fn() -> bool,
            ) -> std::io::Result<Vec<std::io::Result<PathBuf>>> {
                // Mirror `RealFs` precedence: an expired deadline preempts
                // the listing (a 65k listing trips the 64-entry collection
                // gate long before the quota). The test's live deadline
                // still reaches the quota refusal below.
                if deadline() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "directory listing collection crossed the deadline",
                    ));
                }
                Err(std::io::Error::new(
                    std::io::ErrorKind::QuotaExceeded,
                    "listing exceeds scan bound",
                ))
            }

            fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
                RealFs.symlink_metadata(path)
            }

            fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
                RealFs.metadata(path)
            }
        }

        let dir = scratch("listing-cap");
        let root = dir.join("cgroup");
        mkdir(&root.join("child"));
        let view = HostView::new(&dir.join("proc"), &root);
        let mut counters = HelperCounters::new();
        let mut budget = ScanBudget::new();
        let outcome = view.find_cgroups(
            &[u64::MAX - 5],
            &mut counters,
            &CappedFs,
            &mut budget,
            &|| false,
        );
        assert_eq!(outcome, Err(HostReadError::BudgetExceeded));
        assert_eq!(counters.scan_budget_trips, 1);
        assert_eq!(budget.entries_examined(), 0, "nothing examined");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// P2 oracle: the deadline is honored DURING `RealFs` listing
    /// collection, not only during examination. A 5000-entry live
    /// directory plus a call-counting predicate proves the production
    /// gate itself runs — this test drives `RealFs` directly, never a
    /// reimplementation, so removing the production periodic check
    /// fails it (see `evidence/.../red-mutant-new-oracle.log`).
    /// Regression for the review P2 (codex oracle: 4990 entries
    /// collected post-expiry).
    #[test]
    fn scan_deadline_stops_mid_listing_collection() {
        let dir = scratch("listing-deadline");
        let root = dir.join("cgroup");
        mkdir(&root);
        for i in 0..5000 {
            touch(&root.join(format!("entry-{i:05}")));
        }

        // Live deadline: every periodic check plus the pre-sort check
        // must run on the production path — 5000 / 64 = 78 periodic
        // consultations, then 1 pre-sort consultation. A mutant without
        // the periodic gate consults exactly once.
        let consultations = std::cell::Cell::new(0usize);
        let entries = RealFs
            .read_dir_sorted(&root, &|| {
                consultations.set(consultations.get().saturating_add(1));
                false
            })
            .expect("live listing collects");
        let paths: Vec<PathBuf> = entries
            .into_iter()
            .map(|entry| entry.expect("live child reads"))
            .collect();
        assert_eq!(paths.len(), 5000);
        assert!(
            paths.windows(2).all(|pair| pair[0] <= pair[1]),
            "live listing stays sorted"
        );
        assert_eq!(
            consultations.get(),
            78 + 1,
            "5000 live entries must consult the deadline 78 periodic + 1 pre-sort times"
        );

        // Expired mid-collection: the clock trips on the 11th
        // consultation — 704 of 5000 entries collected — and
        // collection stops at that check instead of sweeping the rest.
        let consultations = std::cell::Cell::new(0usize);
        let outcome = RealFs.read_dir_sorted(&root, &|| {
            consultations.set(consultations.get().saturating_add(1));
            consultations.get() >= 11
        });
        let err = outcome.expect_err("expired listing must refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(
            consultations.get(),
            11,
            "collection must stop at the trip consultation, not sweep on"
        );

        // End to end on the live path: `find_cgroups` over `RealFs`
        // with a clock expiring on its 2nd read (the pre-walk check
        // stays live, the first periodic collection check trips)
        // refuses typed [`HostReadError::DeadlineExceeded`] after
        // consulting exactly twice — proof the 5000-entry collection
        // stopped at 64 instead of sweeping.
        let view = HostView::new(&dir.join("proc"), &root);
        let mut counters = HelperCounters::new();
        let mut budget = ScanBudget::new();
        let consultations = std::cell::Cell::new(0usize);
        let outcome = view.find_cgroups(
            &[u64::MAX - 11],
            &mut counters,
            &RealFs,
            &mut budget,
            &|| {
                consultations.set(consultations.get().saturating_add(1));
                consultations.get() >= 2
            },
        );
        assert_eq!(outcome, Err(HostReadError::DeadlineExceeded));
        assert_eq!(counters.deadline_trips, 1);
        assert_eq!(counters.scan_budget_trips, 0);
        assert_eq!(
            consultations.get(),
            2,
            "live-path collection must stop at the first periodic check"
        );
        assert_eq!(
            budget.entries_examined(),
            0,
            "nothing examined past the refused listing"
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
            HostReadError::DeadlineExceeded,
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
