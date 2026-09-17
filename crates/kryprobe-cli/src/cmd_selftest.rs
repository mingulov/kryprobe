// SPDX-License-Identifier: GPL-3.0-or-later
//! Artifact location shared by the BPF selftests (object + sibling bins).

use std::path::PathBuf;

/// Locates the spine object: `KRYPROBE_BPF_OBJ`, else exe-relative
/// `target/kryprobe-bpf/spine.bpf.o`, else CWD-relative.
pub(crate) fn locate_bpf_object() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("KRYPROBE_BPF_OBJ") {
        let path = PathBuf::from(path);
        if !path.as_os_str().is_empty() && path.is_file() {
            return Some(path);
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let path = dir.join("../kryprobe-bpf/spine.bpf.o");
        if path.is_file() {
            return Some(path);
        }
    }
    let path = PathBuf::from("target/kryprobe-bpf/spine.bpf.o");
    if path.is_file() {
        return Some(path);
    }
    None
}

/// Locates a helper binary: `$KRYPROBE_<NAME>` override, else a binary
/// sitting next to the running `kryprobe` executable.
pub(crate) fn sibling_binary(name: &str, env_override: &str) -> Option<PathBuf> {
    if let Ok(path) = std::env::var(env_override) {
        let path = PathBuf::from(path);
        if !path.as_os_str().is_empty() && path.is_file() {
            return Some(path);
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let path = dir.join(name);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}
