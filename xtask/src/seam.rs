// SPDX-License-Identifier: GPL-3.0-or-later
//! Privilege-seam gate (ADR-0002): keep the future broker boundary greppable.
//!
//! While direct-load is the architecture, all privileged kernel entries must
//! stay behind the modules that will one day move across the broker boundary.
//! Two rules, both fail-closed:
//!
//! Rule A — raw entry: `libc::syscall(` call sites exist only in the
//! allowlisted files (the bpf() wrapper, pidfd_open, the token mount flow).
//! A new raw entry point anywhere else fails the gate.
//!
//! Rule B — containment: outside `crates/kryprobe-privilege/`, the only
//! `libc::name(` calls are benign identity getters. Backends, core, CLI,
//! and report code perform no privileged syscalls, directly or otherwise.
//!
//! Comment handling: the whole file is scrubbed before scanning — line
//! comments, (nestable, multi-line) block comments, string literals
//! (ordinary, byte, and raw), and char literals are blanked, with
//! newlines preserved so line numbers hold. A `//` inside a string must
//! not hide a real call, a call name inside a comment or a literal must
//! not trip the gate, and a quote inside a char (`'"'`) must not blank
//! the real call after it. Lifetime ticks are never blanked (only strict
//! `'c'`/escape char shapes are), so scrubbing cannot hide code.

use std::path::{Path, PathBuf};

/// Files allowed to contain raw `libc::syscall(` entry points,
/// workspace-relative with `/` separators.
const SYS_ALLOW: &[&str] = &[
    "crates/kryprobe-privilege/src/probe/bpf_sys.rs",
    "crates/kryprobe-privilege/src/inspect.rs",
    "crates/kryprobe-privilege/src/token/mint.rs",
];

/// `libc::name(` calls allowed outside `crates/kryprobe-privilege/`.
const CALL_ALLOW: &[&str] = &["geteuid", "getegid", "getpid", "getppid"];

/// Per-file Rule-B exceptions: (workspace-relative file, extra allowed
/// `libc::name(` calls). The K1 Task-2 `AF_ALG` fixture performs
/// unprivileged socket I/O only — any uid may `socket`/`bind`/`send`/
/// `recv` on `AF_ALG`; no capability, no BPF, no mount/pidfd/netlink —
/// so the seam's privilege-containment intent is preserved. Scoped to
/// the one justified file (K1 Task-2 brief mandates the testkit
/// placement); anything else there still trips.
const FILE_CALL_ALLOW: &[(&str, &[&str])] = &[(
    "crates/kryprobe-testkit/src/alg_fixture.rs",
    &[
        "accept",
        "bind",
        "clock_gettime",
        "close",
        "read",
        "send",
        "sendmsg",
        "setsockopt",
        "socket",
    ],
)];

/// True when `name` is allowed in `rel` by the per-file exceptions.
fn file_allows(rel: &str, name: &str) -> bool {
    FILE_CALL_ALLOW
        .iter()
        .any(|(file, names)| *file == rel && names.contains(&name))
}

/// Privilege crate prefix (workspace-relative, `/` separators).
const PRIV_PREFIX: &str = "crates/kryprobe-privilege/";

/// One gate violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Violation {
    /// Workspace-relative path with `/` separators.
    pub(crate) file: String,
    /// 1-based line number.
    pub(crate) line: usize,
    /// `A` (raw entry) or `B` (containment).
    pub(crate) rule: char,
}

/// End offset (exclusive) of the char literal at byte `i`, or `None`
/// when the quote is a lifetime tick. Only strict char shapes (`'c'`
/// and backslash escapes) blank; anything else is left untouched, so a
/// lifetime can never eat the code after it and hide a real call.
fn char_end(bytes: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    if bytes.get(j) == Some(&b'\\') {
        j += 1;
        match bytes.get(j) {
            Some(b'x') => j += 3,
            Some(b'u') => {
                j += 1;
                if bytes.get(j) != Some(&b'{') {
                    return None;
                }
                j += 1;
                let mut digits = 0;
                while bytes.get(j).is_some_and(|b| b.is_ascii_hexdigit()) && digits < 6 {
                    j += 1;
                    digits += 1;
                }
                if digits == 0 || bytes.get(j) != Some(&b'}') {
                    return None;
                }
                j += 1;
            }
            Some(_) => j += 1,
            None => return None,
        }
    } else {
        match bytes.get(j) {
            Some(b'\'') | Some(b'\n') | None => return None,
            _ => j += 1,
        }
    }
    if bytes.get(j) == Some(&b'\'') {
        Some(j + 1)
    } else {
        None
    }
}

/// Whole-file scrub: blank comments and literals, preserving newlines.
/// Line comments run to end-of-line; block comments nest and may span
/// lines; strings honor backslash escapes (including line continuations)
/// and raw `r#*"..."*#` quoting. An unterminated string stops at
/// end-of-line (invalid Rust; blanking less never hides a real call).
fn scrubbed(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    let blank = |out: &mut [u8], from: usize, to: usize| {
        for byte in &mut out[from..to] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    };
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            let mut j = i;
            while j < bytes.len() && bytes[j] != b'\n' {
                j += 1;
            }
            blank(&mut out, i, j);
            i = j;
            continue;
        }
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            let mut j = i + 2;
            let mut depth = 1_usize;
            while j < bytes.len() && depth > 0 {
                if bytes[j] == b'/' && bytes.get(j + 1) == Some(&b'*') {
                    depth += 1;
                    j += 2;
                } else if bytes[j] == b'*' && bytes.get(j + 1) == Some(&b'/') {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
            continue;
        }
        if bytes[i] == b'r' {
            let mut j = i + 1;
            while bytes.get(j) == Some(&b'#') {
                j += 1;
            }
            if bytes.get(j) == Some(&b'"') {
                let hashes = j - (i + 1);
                j += 1;
                let mut end = bytes.len();
                while j < bytes.len() {
                    if bytes[j] == b'"' {
                        let mut k = j + 1;
                        let mut seen = 0;
                        while seen < hashes && bytes.get(k) == Some(&b'#') {
                            seen += 1;
                            k += 1;
                        }
                        if seen == hashes {
                            end = k;
                            break;
                        }
                    }
                    j += 1;
                }
                blank(&mut out, i, end);
                i = end;
                continue;
            }
        }
        if bytes[i] == b'"' {
            let mut j = i + 1;
            while j < bytes.len() {
                if bytes[j] == b'\\' {
                    j += 2;
                } else if bytes[j] == b'"' {
                    j += 1;
                    break;
                } else if bytes[j] == b'\n' {
                    break;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
            continue;
        }
        if bytes[i] == b'\''
            && let Some(j) = char_end(bytes, i)
        {
            blank(&mut out, i, j);
            i = j;
            continue;
        }
        i += 1;
    }
    match String::from_utf8(out) {
        Ok(clean) => clean,
        // 1A-L1: unreachable (blanking writes spaces over whole
        // chars only) — but a corrupt future must fail CLOSED: scan
        // unscrubbed so the gate flags more, never less.
        Err(_) => text.to_owned(),
    }
}

/// `libc::name(` call names on one comment-stripped line, in order.
fn libc_calls(code: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = code.as_bytes();
    let mut i = 0;
    while i + 7 <= bytes.len() {
        if code[i..].starts_with("libc::") {
            let mut j = i + 6;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            let name = &code[i + 6..j];
            let mut k = j;
            while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                k += 1;
            }
            if !name.is_empty()
                && name.as_bytes()[0].is_ascii_lowercase()
                && k < bytes.len()
                && bytes[k] == b'('
            {
                out.push(name);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

/// Violations in one file's text. `rel` is workspace-relative (`/` seps).
/// Both rules scan scrubbed lines through the [`libc_calls`] parser, so
/// a call spelled inside a comment or a literal never trips either rule
/// — and `libc::syscall (` with whitespace trips Rule A instead of
/// evading the old exact-substring check.
fn violations_in_source(rel: &str, text: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    let in_privilege = rel.starts_with(PRIV_PREFIX);
    let clean = scrubbed(text);
    for (index, line) in clean.lines().enumerate() {
        let calls = libc_calls(line);
        if calls.contains(&"syscall") && !SYS_ALLOW.contains(&rel) {
            out.push(Violation {
                file: rel.to_owned(),
                line: index + 1,
                rule: 'A',
            });
        }
        if !in_privilege {
            for name in calls {
                if name != "syscall" && !CALL_ALLOW.contains(&name) && !file_allows(rel, name) {
                    out.push(Violation {
                        file: rel.to_owned(),
                        line: index + 1,
                        rule: 'B',
                    });
                }
            }
        }
    }
    out
}

/// Collect `*.rs` files under `dir`, skipping `target/` and hidden dirs.
fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)?.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let hidden = name.to_string_lossy().starts_with('.');
        if path.is_dir() {
            if name == "target" || hidden {
                continue;
            }
            collect_rs(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") && !hidden {
            out.push(path);
        }
    }
    Ok(())
}

/// Walk up to the workspace root (holds `crates/kryprobe-privilege/`).
fn workspace_root() -> Option<PathBuf> {
    crate::root::climb_to("crates/kryprobe-privilege")
}

/// Scan the tree; nonempty means the gate fails.
pub(crate) fn find_violations(root: &Path) -> Vec<Violation> {
    let mut files = Vec::new();
    if collect_rs(&root.join("crates"), &mut files).is_err() {
        return vec![Violation {
            file: "<crates>".to_owned(),
            line: 0,
            rule: '?',
        }];
    }
    let mut out = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        out.extend(violations_in_source(&rel, &text));
    }
    out.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
    out
}

/// xtask `check` step: 0 when the seam holds, 1 with details otherwise.
pub(crate) fn check_seam() -> i32 {
    let Some(root) = workspace_root() else {
        eprintln!(
            "xtask check: cannot find workspace root (no crates/kryprobe-privilege above here)"
        );
        return 1;
    };
    let violations = find_violations(&root);
    if violations.is_empty() {
        println!("+ seam: privilege boundary holds");
        return 0;
    }
    eprintln!("xtask check: privilege-seam violations (ADR-0002):");
    for v in &violations {
        eprintln!("  {}:{}: rule {} tripped", v.file, v.line, v.rule);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_a_allows_listed_wrappers() {
        for rel in SYS_ALLOW {
            let text = "    unsafe { libc::syscall(libc::SYS_bpf, 0, 0, 0) }\n";
            assert!(violations_in_source(rel, text).is_empty(), "{rel}");
        }
    }

    #[test]
    fn rule_a_flags_new_raw_entry() {
        let text = "let r = unsafe { libc::syscall(libc::SYS_bpf, 0, 0, 0) };\n";
        let found = violations_in_source("crates/kryprobe-core/src/sneaky.rs", text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule, 'A');
        assert_eq!(found[0].line, 1);
    }

    #[test]
    fn rule_a_ignores_comments() {
        let text = "// mentions libc::syscall( in a comment\n//! doc libc::syscall(\nlet x = 1; // trailing libc::syscall(\n";
        assert!(violations_in_source("crates/kryprobe-core/src/x.rs", text).is_empty());
    }

    #[test]
    fn rule_a_sees_past_string_slashes() {
        // A `//` inside a string must not hide the real call after it.
        let text = "let u = \"http://x\"; unsafe { libc::syscall(1, 2, 3, 4) };\n";
        let found = violations_in_source("crates/kryprobe-core/src/x.rs", text);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn rule_a_ignores_call_spelled_in_literals() {
        let text = "let s = \"libc::syscall(\";\nlet r = r#\"libc::syscall(\"#;\nlet b = b\"libc::syscall(\";\n";
        assert!(violations_in_source("crates/kryprobe-core/src/x.rs", text).is_empty());
    }

    #[test]
    fn rule_a_ignores_call_spelled_in_block_comments() {
        let text = "/* libc::syscall( */ let x = 1;\n/* outer /* nested libc::syscall( */ still comment */\n";
        assert!(violations_in_source("crates/kryprobe-core/src/x.rs", text).is_empty());
        // Multi-line block comments hide their whole span, line numbers hold.
        let text = "/*\nlibc::syscall(\n*/\nlet y = unsafe { libc::syscall(1, 2, 3, 4) };\n";
        let found = violations_in_source("crates/kryprobe-core/src/x.rs", text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 4);
    }

    #[test]
    fn rule_a_sees_whitespace_before_paren() {
        // The old exact-substring check missed this spelling entirely.
        let text = "unsafe { libc::syscall (1, 2, 3, 4) };\n";
        let found = violations_in_source("crates/kryprobe-core/src/x.rs", text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule, 'A');
    }

    #[test]
    fn scrubber_keeps_chars_but_never_lifetimes() {
        // A quote inside a char must not blank the real call after it.
        let text = "let q = '\"'; unsafe { libc::syscall(1, 2, 3, 4) };\n";
        assert_eq!(
            violations_in_source("crates/kryprobe-core/src/x.rs", text).len(),
            1
        );
        // Lifetime ticks never blank: the call after one still trips.
        let text = "fn f(x: &'static str) { unsafe { libc::syscall(1, 2, 3, 4) } }\n";
        assert_eq!(
            violations_in_source("crates/kryprobe-core/src/x.rs", text).len(),
            1
        );
    }

    #[test]
    fn rule_b_ignores_call_spelled_in_literal_or_block_comment() {
        let text = "let s = \"libc::fork(\";\n/* libc::epoll_create1( */\n";
        assert!(violations_in_source("crates/kryprobe-cli/src/x.rs", text).is_empty());
    }

    #[test]
    fn rule_b_allows_identity_getters_elsewhere() {
        let text = "if unsafe { libc::geteuid() } != 0 {}\nlet p = unsafe { libc::getpid() };\n";
        assert!(violations_in_source("crates/kryprobe-cli/src/x.rs", text).is_empty());
    }

    #[test]
    fn rule_b_flags_privileged_calls_elsewhere() {
        let text = "unsafe { libc::fork() };\nunsafe { libc::epoll_create1(0) };\n";
        let found = violations_in_source("crates/kryprobe-core/src/x.rs", text);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|v| v.rule == 'B'));
    }

    #[test]
    fn rule_b_ignores_types_consts_and_spacing() {
        let text = "fn f(p: *mut libc::c_char, e: libc::EBADF) {}\nlet x: libc::c_int = 0;\n";
        assert!(violations_in_source("crates/kryprobe-core/src/x.rs", text).is_empty());
        // Whitespace before the paren still counts as a call.
        let text = "unsafe { libc::fork () };\n";
        assert_eq!(
            violations_in_source("crates/kryprobe-core/src/x.rs", text).len(),
            1
        );
    }

    #[test]
    fn rule_b_file_exception_allows_fixture_socket_calls() {
        let rel = "crates/kryprobe-testkit/src/alg_fixture.rs";
        let text = "unsafe { libc::socket(0, 0, 0) }; unsafe { libc::bind(0, 0, 0) };\n\
             unsafe { libc::setsockopt(0, 0, 0, 0, 0) }; unsafe { libc::accept(0, 0, 0) };\n\
             unsafe { libc::sendmsg(0, 0, 0) }; unsafe { libc::send(0, 0, 0, 0) };\n\
             unsafe { libc::read(0, 0, 0) }; unsafe { libc::close(0) };\n\
             unsafe { libc::clock_gettime(0, 0) };\n";
        assert!(violations_in_source(rel, text).is_empty());
    }

    #[test]
    fn rule_b_file_exception_is_file_scoped() {
        // The same calls in any other file still trip (one per line).
        let text = "unsafe { libc::socket(0, 0, 0) }; unsafe { libc::bind(0, 0, 0) };\n";
        let found = violations_in_source("crates/kryprobe-core/src/x.rs", text);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|v| v.rule == 'B'));
    }

    #[test]
    fn rule_b_file_exception_does_not_allow_other_calls() {
        // The fixture file gets no blanket pass: anything outside its
        // socket-I/O set still trips.
        let rel = "crates/kryprobe-testkit/src/alg_fixture.rs";
        let text = "unsafe { libc::fork() };\nunsafe { libc::epoll_create1(0) };\n";
        let found = violations_in_source(rel, text);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|v| v.rule == 'B'));
    }

    #[test]
    fn rule_b_does_not_apply_inside_privilege() {
        let text = "unsafe { libc::fork() };\nunsafe { libc::epoll_create1(0) };\n";
        assert!(
            violations_in_source("crates/kryprobe-privilege/src/drain/worker.rs", text).is_empty()
        );
    }
}
