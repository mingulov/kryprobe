// SPDX-License-Identifier: GPL-3.0-or-later
//! Fixed helper IPC: one stdin snapshot request in, one stdout snapshot
//! response out, JSON diagnostics on stderr. Plus self-attestation.
//!
//! M1 protocol (fixed, no negotiation):
//!
//! - stdin carries exactly one [`SnapshotRequest`] JSON document, read to
//!   EOF and bounded by [`MAX_SNAPSHOT_REQUEST_BYTES`] (byte budget
//!   before parsing, via [`decode_request`]).
//! - stdout carries exactly one [`SnapshotResponse`] JSON document,
//!   validated and budgeted by [`encode_response`]. Refusals leave stdout
//!   empty: there are no partial responses on the wire.
//! - stderr carries newline-delimited JSON: one `{"attestation":{...}}`
//!   line, zero or more `{"error":"<name>"}` lines (whole-request typed
//!   refusals reusing the frozen [`MetadataUnavailable`] vocabulary), and
//!   one final `{"helper_counters":{...}}` line. Every line is IDs-only:
//!   numeric ids, counters, and fixed strings — never paths or untrusted
//!   input bytes.
//!
//! [`SnapshotRequest`]: kryprobe_core::workload::SnapshotRequest
//! [`SnapshotResponse`]: kryprobe_core::workload::SnapshotResponse
//! [`MAX_SNAPSHOT_REQUEST_BYTES`]: kryprobe_core::workload::MAX_SNAPSHOT_REQUEST_BYTES
//! [`decode_request`]: kryprobe_core::workload::decode_request
//! [`encode_response`]: kryprobe_core::workload::encode_response
//! [`MetadataUnavailable`]: kryprobe_core::workload::MetadataUnavailable

use kryprobe_core::workload::{
    MAX_SNAPSHOT_REQUEST_BYTES, MetadataUnavailable, SnapshotRequest, SnapshotResponse,
    decode_request, encode_response,
};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

/// Success: exactly one response document was written to stdout.
pub const EXIT_OK: i32 = 0;
/// Typed refusal or failure: stderr carries `{"error":"<name>"}`.
pub const EXIT_REFUSED: i32 = 1;
/// Command-line usage error.
pub const EXIT_USAGE: i32 = 2;

/// Read one request with a wall-clock deadline for slow senders: the read
/// runs on a helper thread and a lapse refuses [`MetadataUnavailable::HelperRefused`].
/// The reader thread is detached past the deadline (it ends on EOF/error);
/// callers must not reuse the reader afterwards.
pub fn read_request_with_timeout<R: Read + Send + 'static>(
    reader: R,
    max_bytes: usize,
    timeout: Duration,
) -> Result<SnapshotRequest, MetadataUnavailable> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(read_request_capped(reader, max_bytes));
    });
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(_) => Err(MetadataUnavailable::HelperRefused),
    }
}

/// Bounded stdin drain shared by both readers.
fn read_request_capped<R: Read>(
    mut reader: R,
    max_bytes: usize,
) -> Result<SnapshotRequest, MetadataUnavailable> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let Some(room) = max_bytes
            .checked_add(1)
            .and_then(|cap| cap.checked_sub(bytes.len()))
        else {
            return Err(MetadataUnavailable::BudgetExceeded);
        };
        if room == 0 {
            return Err(MetadataUnavailable::BudgetExceeded);
        }
        let want = room.min(chunk.len());
        let read = reader
            .read(&mut chunk[..want])
            .map_err(|_| MetadataUnavailable::HelperRefused)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > max_bytes {
            return Err(MetadataUnavailable::BudgetExceeded);
        }
    }
    if bytes.is_empty() {
        return Err(MetadataUnavailable::ParseFailed);
    }
    decode_request(&bytes)
}

/// Validate, budget, and write one response document. Any serialization
/// or write failure refuses typed: the caller must exit nonzero without
/// claiming success.
pub fn write_response<W: Write>(
    mut writer: W,
    response: &SnapshotResponse,
) -> Result<(), MetadataUnavailable> {
    let bytes = encode_response(response)?;
    writer
        .write_all(&bytes)
        .map_err(|_| MetadataUnavailable::HelperRefused)?;
    writer
        .flush()
        .map_err(|_| MetadataUnavailable::HelperRefused)?;
    Ok(())
}

/// One stderr JSON error line for a whole-request refusal, reusing the
/// frozen `MetadataUnavailable` snake-case names (`no_principal`,
/// `helper_refused`, `budget_exceeded`, `unsupported_environment`,
/// `parse_failed`).
#[must_use]
pub fn error_line(kind: MetadataUnavailable) -> String {
    let name = serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "helper_refused".to_string());
    format!(r#"{{"error":{name:?}}}"#)
}

/// Self-attestation: the helper's own unprivileged boundary, established
/// from kernel state (`/proc/self/status`, `/proc/self/fd`) — never from
/// environment variables. All fields are numeric ids or flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// Real uid.
    pub uid: u32,
    /// Effective uid.
    pub euid: u32,
    /// Real gid.
    pub gid: u32,
    /// Effective gid.
    pub egid: u32,
    /// Effective capabilities mask.
    pub cap_eff: u64,
    /// Permitted capabilities mask.
    pub cap_prm: u64,
    /// Inheritable capabilities mask.
    pub cap_inh: u64,
    /// Ambient capabilities mask.
    pub cap_amb: u64,
    /// Whether no-new-privs is set.
    pub no_new_privs: bool,
    /// Inherited descriptor numbers (must be exactly stdio).
    pub fds: Vec<u32>,
}

/// Collect attestation from the live process (`/proc/self`). This is
/// self-inspection, not host-view reading: the `--proc-root` fixture
/// override never applies here. Unreadable or unparsable kernel state
/// refuses [`MetadataUnavailable::UnsupportedEnvironment`]; diagnostics
/// never echo file bytes.
pub fn collect_attestation() -> Result<Attestation, MetadataUnavailable> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|_| MetadataUnavailable::UnsupportedEnvironment)?;
    let parsed = parse_status(&status).ok_or(MetadataUnavailable::UnsupportedEnvironment)?;
    let fd_dir = Path::new("/proc/self/fd");
    let entries =
        std::fs::read_dir(fd_dir).map_err(|_| MetadataUnavailable::UnsupportedEnvironment)?;
    let mut fds = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| MetadataUnavailable::UnsupportedEnvironment)?;
        let name = entry.file_name();
        let text = name
            .to_str()
            .ok_or(MetadataUnavailable::UnsupportedEnvironment)?;
        let fd: u32 = text
            .parse()
            .map_err(|_| MetadataUnavailable::UnsupportedEnvironment)?;
        fds.push(fd);
    }
    fds.sort_unstable();
    // The directory read itself holds one transient fd: lowest-free
    // allocation makes it the highest number. Drop exactly it.
    let Some(_transient) = fds.pop() else {
        return Err(MetadataUnavailable::UnsupportedEnvironment);
    };
    Ok(Attestation {
        uid: parsed.uid,
        euid: parsed.euid,
        gid: parsed.gid,
        egid: parsed.egid,
        cap_eff: parsed.cap_eff,
        cap_prm: parsed.cap_prm,
        cap_inh: parsed.cap_inh,
        cap_amb: parsed.cap_amb,
        no_new_privs: parsed.no_new_privs,
        fds,
    })
}

/// Parsed `/proc/self/status` identity/capability fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedStatus {
    uid: u32,
    euid: u32,
    gid: u32,
    egid: u32,
    cap_eff: u64,
    cap_prm: u64,
    cap_inh: u64,
    cap_amb: u64,
    no_new_privs: bool,
}

/// Parse the attestation fields out of status text. Returns `None` on any
/// missing or malformed field (fail closed, no partial identity).
fn parse_status(text: &str) -> Option<ParsedStatus> {
    let mut uid = None;
    let mut euid = None;
    let mut gid = None;
    let mut egid = None;
    let mut cap_eff = None;
    let mut cap_prm = None;
    let mut cap_inh = None;
    let mut cap_amb = None;
    let mut no_new_privs = None;
    for line in text.lines() {
        let (key, rest) = line.split_once(':')?;
        let value = rest.trim();
        match key {
            "Uid" => {
                let mut parts = value.split_whitespace();
                uid = parts.next()?.parse().ok();
                euid = parts.next()?.parse().ok();
            }
            "Gid" => {
                let mut parts = value.split_whitespace();
                gid = parts.next()?.parse().ok();
                egid = parts.next()?.parse().ok();
            }
            "CapEff" => cap_eff = u64::from_str_radix(value, 16).ok(),
            "CapPrm" => cap_prm = u64::from_str_radix(value, 16).ok(),
            "CapInh" => cap_inh = u64::from_str_radix(value, 16).ok(),
            "CapAmb" => cap_amb = u64::from_str_radix(value, 16).ok(),
            "NoNewPrivs" => no_new_privs = Some(value == "1"),
            _ => {}
        }
    }
    Some(ParsedStatus {
        uid: uid?,
        euid: euid?,
        gid: gid?,
        egid: egid?,
        cap_eff: cap_eff?,
        cap_prm: cap_prm?,
        cap_inh: cap_inh?,
        cap_amb: cap_amb?,
        no_new_privs: no_new_privs?,
    })
}

/// Enforce the unprivileged boundary, before any metadata or request byte
/// is parsed:
///
/// - root (uid or euid 0) with no trustworthy non-root principal refuses
///   [`MetadataUnavailable::NoPrincipal`]: M1 has no principal-passing
///   mechanism, so root invocation retains raw-ID capture and yields typed
///   metadata-unavailable.
/// - any non-empty capability set, a non-stdio fd set, or (when
///   `require_no_new_privs`) a clear no-new-privs flag refuses
///   [`MetadataUnavailable::HelperRefused`].
pub fn check_attestation(
    attestation: &Attestation,
    require_no_new_privs: bool,
) -> Result<(), MetadataUnavailable> {
    if attestation.uid == 0 || attestation.euid == 0 {
        return Err(MetadataUnavailable::NoPrincipal);
    }
    if attestation.cap_eff != 0
        || attestation.cap_prm != 0
        || attestation.cap_inh != 0
        || attestation.cap_amb != 0
    {
        return Err(MetadataUnavailable::HelperRefused);
    }
    if attestation.fds != [0, 1, 2] {
        return Err(MetadataUnavailable::HelperRefused);
    }
    if require_no_new_privs && !attestation.no_new_privs {
        return Err(MetadataUnavailable::HelperRefused);
    }
    Ok(())
}

/// The `{"attestation":{...}}` stderr/stdout line. Capability masks render
/// as decimal strings so 64-bit values survive JSON consumers without
/// precision loss (spec §5.4 integer convention).
#[must_use]
pub fn attestation_line(attestation: &Attestation) -> String {
    serde_json::json!({
        "attestation": {
            "uid": attestation.uid,
            "euid": attestation.euid,
            "gid": attestation.gid,
            "egid": attestation.egid,
            "caps": {
                "eff": attestation.cap_eff.to_string(),
                "prm": attestation.cap_prm.to_string(),
                "inh": attestation.cap_inh.to_string(),
                "amb": attestation.cap_amb.to_string(),
            },
            "no_new_privs": attestation.no_new_privs,
            "fds": attestation.fds,
        }
    })
    .to_string()
}

/// Default stdin budget: the frozen request bound.
#[must_use]
pub const fn default_request_budget() -> usize {
    MAX_SNAPSHOT_REQUEST_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;
    use kryprobe_core::workload::{SnapshotKey, SnapshotRequest};
    use std::io::Cursor;
    use std::sync::mpsc as std_mpsc;

    const SESSION: &str = "0123456789abcdef0123456789abcdef";

    fn request_bytes() -> Vec<u8> {
        let request = SnapshotRequest {
            session_id: SESSION.to_string(),
            keys: vec![SnapshotKey {
                kernel_scope: "k".to_string(),
                cgroup: 1,
                tgid: 1,
                start_ns: 1,
            }],
        };
        serde_json::to_vec(&request).expect("encodes")
    }

    fn read_fast(bytes: Vec<u8>) -> Result<SnapshotRequest, MetadataUnavailable> {
        read_request_with_timeout(
            Cursor::new(bytes),
            default_request_budget(),
            Duration::from_secs(5),
        )
    }

    #[test]
    fn valid_request_round_trips() {
        let request = read_fast(request_bytes()).expect("valid reads");
        assert_eq!(request.session_id, SESSION);
        assert_eq!(request.keys.len(), 1);
    }

    #[test]
    fn empty_stdin_is_parse_failed() {
        assert_eq!(read_fast(Vec::new()), Err(MetadataUnavailable::ParseFailed));
    }

    #[test]
    fn over_budget_stdin_refuses_before_parsing() {
        let big = vec![b'{'; default_request_budget() + 1];
        assert_eq!(read_fast(big), Err(MetadataUnavailable::BudgetExceeded));
    }

    #[test]
    fn malformed_stdin_is_parse_failed() {
        assert_eq!(
            read_fast(b"{oops".to_vec()),
            Err(MetadataUnavailable::ParseFailed)
        );
    }

    /// A sender that never delivers trips the timeout instead of hanging
    /// the helper: slow readers refuse typed.
    #[test]
    fn slow_reader_trips_timeout() {
        struct BlockingReader {
            rx: std_mpsc::Receiver<u8>,
        }
        impl Read for BlockingReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                // Block until the peer disappears; the timeout fires first.
                match self.rx.recv() {
                    Ok(_) => Ok(0),
                    Err(_) => Ok(0),
                }
            }
        }
        let (_tx, rx) = std_mpsc::channel();
        let start = std::time::Instant::now();
        let result = read_request_with_timeout(
            BlockingReader { rx },
            default_request_budget(),
            Duration::from_millis(100),
        );
        assert_eq!(result, Err(MetadataUnavailable::HelperRefused));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "timeout must bound the wait"
        );
    }

    #[test]
    fn fast_reader_beats_timeout() {
        let result = read_request_with_timeout(
            Cursor::new(request_bytes()),
            default_request_budget(),
            Duration::from_secs(5),
        )
        .expect("fast reads");
        assert_eq!(result.keys.len(), 1);
    }

    #[test]
    fn write_failure_refuses_typed() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk full"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("disk full"))
            }
        }
        let response = kryprobe_core::workload::resolve(
            &SnapshotRequest {
                session_id: SESSION.to_string(),
                keys: vec![SnapshotKey {
                    kernel_scope: "k".to_string(),
                    cgroup: 1,
                    tgid: 1,
                    start_ns: 1,
                }],
            },
            &kryprobe_core::workload::MetadataSnapshot {
                collector: "t".to_string(),
                snapshot_interval: kryprobe_core::workload::SnapshotInterval {
                    start_ns: 1,
                    end_ns: 2,
                },
                kernel_identity: kryprobe_core::workload::KernelIdentity::Known("k".to_string()),
                entries: Vec::new(),
            },
        )
        .expect("resolves");
        assert_eq!(
            write_response(FailingWriter, &response),
            Err(MetadataUnavailable::HelperRefused)
        );
    }

    #[test]
    fn error_lines_reuse_frozen_names() {
        assert!(error_line(MetadataUnavailable::NoPrincipal).contains("no_principal"));
        assert!(error_line(MetadataUnavailable::HelperRefused).contains("helper_refused"));
        assert!(error_line(MetadataUnavailable::BudgetExceeded).contains("budget_exceeded"));
        assert!(
            error_line(MetadataUnavailable::UnsupportedEnvironment)
                .contains("unsupported_environment")
        );
        assert!(error_line(MetadataUnavailable::ParseFailed).contains("parse_failed"));
    }

    fn status_text(uid: u32, euid: u32, caps: &str, nnp: &str) -> String {
        format!(
            "Uid:\t{uid}\t{euid}\t{euid}\t{euid}\nGid:\t1000\t1000\t1000\t1000\nCapEff:\t{caps}\nCapPrm:\t{caps}\nCapInh:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t{nnp}\n"
        )
    }

    fn attestation_from(uid: u32, euid: u32, caps: &str, nnp: &str, fds: Vec<u32>) -> Attestation {
        let parsed = parse_status(&status_text(uid, euid, caps, nnp)).expect("parses");
        Attestation {
            uid: parsed.uid,
            euid: parsed.euid,
            gid: parsed.gid,
            egid: parsed.egid,
            cap_eff: parsed.cap_eff,
            cap_prm: parsed.cap_prm,
            cap_inh: parsed.cap_inh,
            cap_amb: parsed.cap_amb,
            no_new_privs: parsed.no_new_privs,
            fds,
        }
    }

    #[test]
    fn ordinary_attestation_passes() {
        let att = attestation_from(1000, 1000, "0000000000000000", "0", vec![0, 1, 2]);
        assert!(check_attestation(&att, false).is_ok());
    }

    #[test]
    fn root_is_no_principal() {
        for (uid, euid) in [(0, 0), (0, 1000), (1000, 0)] {
            let att = attestation_from(uid, euid, "0000000000000000", "1", vec![0, 1, 2]);
            assert_eq!(
                check_attestation(&att, false),
                Err(MetadataUnavailable::NoPrincipal),
                "uid={uid} euid={euid}"
            );
        }
    }

    #[test]
    fn any_capability_refuses() {
        for caps in ["0000000000000001", "0000000000400000", "ffffffffffffffff"] {
            let att = attestation_from(1000, 1000, caps, "1", vec![0, 1, 2]);
            assert_eq!(
                check_attestation(&att, false),
                Err(MetadataUnavailable::HelperRefused),
                "caps={caps}"
            );
        }
    }

    #[test]
    fn extra_inherited_fd_refuses() {
        let att = attestation_from(1000, 1000, "0000000000000000", "1", vec![0, 1, 2, 3]);
        assert_eq!(
            check_attestation(&att, false),
            Err(MetadataUnavailable::HelperRefused)
        );
        // Missing stdio likewise refuses: the FD set is exact.
        let att = attestation_from(1000, 1000, "0000000000000000", "1", vec![1, 2]);
        assert_eq!(
            check_attestation(&att, false),
            Err(MetadataUnavailable::HelperRefused)
        );
    }

    #[test]
    fn required_no_new_privs_is_enforced() {
        let clear = attestation_from(1000, 1000, "0000000000000000", "0", vec![0, 1, 2]);
        assert_eq!(
            check_attestation(&clear, true),
            Err(MetadataUnavailable::HelperRefused)
        );
        let set = attestation_from(1000, 1000, "0000000000000000", "1", vec![0, 1, 2]);
        assert!(check_attestation(&set, true).is_ok());
    }

    #[test]
    fn malformed_status_fails_closed() {
        assert!(parse_status("Uid:\tnot numbers\n").is_none());
        assert!(parse_status(&status_text(1000, 1000, "zzzz", "0")).is_none());
        assert!(parse_status("").is_none());
        let missing_nnp =
            status_text(1000, 1000, "0000000000000000", "0").replace("NoNewPrivs:\t0\n", "");
        assert!(parse_status(&missing_nnp).is_none());
    }

    #[test]
    fn live_self_collection_succeeds() {
        // Smoke: the live /proc/self reads work in the test process.
        // Precise boundary assertions live in the binary-level suite.
        let attestation = collect_attestation().expect("self reads");
        assert!(!attestation.fds.is_empty());
    }

    #[test]
    fn attestation_line_is_ids_only() {
        let att = attestation_from(1000, 1000, "0000000000000000", "1", vec![0, 1, 2]);
        let line = attestation_line(&att);
        let value: serde_json::Value = serde_json::from_str(&line).expect("JSON");
        assert_eq!(value["attestation"]["caps"]["eff"], "0");
        assert!(!line.contains('/'), "no paths: {line}");
    }
}
