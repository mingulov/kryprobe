// SPDX-License-Identifier: GPL-3.0-or-later
//! Artifact location shared by the BPF selftests (object + sibling bins).

use std::path::PathBuf;

/// Spine-object tiers, pure over the inputs: `KRYPROBE_BPF_OBJ`
/// (non-empty existing file), else exe-relative
/// `../kryprobe-bpf/spine.bpf.o`, else CWD-relative
/// `target/kryprobe-bpf/spine.bpf.o`.
///
/// When `elevated`, env and CWD tiers are refused (H-SEC-01): an
/// elevated selftest never loads an env/CWD-steered object.
fn bpf_object_candidates(
    env: Option<&str>,
    exe_dir: Option<&std::path::Path>,
    elevated: bool,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !elevated && let Some(value) = env {
        let path = PathBuf::from(value);
        if !path.as_os_str().is_empty() && path.is_file() {
            out.push(path);
        }
    }
    if let Some(dir) = exe_dir {
        let path = dir.join("../kryprobe-bpf/spine.bpf.o");
        if path.is_file() {
            out.push(path);
        }
    }
    if !elevated {
        let path = PathBuf::from("target/kryprobe-bpf/spine.bpf.o");
        if path.is_file() {
            out.push(path);
        }
    }
    out
}

/// Locates the spine object: `KRYPROBE_BPF_OBJ`, else exe-relative
/// `target/kryprobe-bpf/spine.bpf.o`, else CWD-relative (env/CWD tiers
/// refused when elevated).
pub(crate) fn locate_bpf_object() -> Option<PathBuf> {
    let elevated = kryprobe_privilege::elevate::process_is_elevated();
    let env = std::env::var("KRYPROBE_BPF_OBJ").ok();
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf));
    bpf_object_candidates(env.as_deref(), exe_dir.as_deref(), elevated)
        .into_iter()
        .next()
}

/// Helper-binary tiers, pure over the inputs: `$KRYPROBE_<NAME>`
/// override (non-empty existing file), else a binary sitting next to
/// the running `kryprobe` executable.
///
/// When `elevated`, the env tier is refused (L-SEC-04): an elevated
/// selftest never executes an env-steered helper.
fn sibling_candidates(
    name: &str,
    env: Option<&str>,
    exe_dir: Option<&std::path::Path>,
    elevated: bool,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !elevated && let Some(value) = env {
        let path = PathBuf::from(value);
        if !path.as_os_str().is_empty() && path.is_file() {
            out.push(path);
        }
    }
    if let Some(dir) = exe_dir {
        let path = dir.join(name);
        if path.is_file() {
            out.push(path);
        }
    }
    out
}

/// Locates a helper binary: `$KRYPROBE_<NAME>` override, else a binary
/// sitting next to the running `kryprobe` executable (env tier refused
/// when elevated).
pub(crate) fn sibling_binary(name: &str, env_override: &str) -> Option<PathBuf> {
    let elevated = kryprobe_privilege::elevate::process_is_elevated();
    let env = std::env::var(env_override).ok();
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf));
    sibling_candidates(name, env.as_deref(), exe_dir.as_deref(), elevated)
        .into_iter()
        .next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("kryprobe-selftest-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn bpf_object_candidates_honor_tiers_unelevated() {
        let dir = scratch("cand");
        let env_file = dir.join("custom-spine.o");
        std::fs::write(&env_file, b"obj").expect("write env file");
        let exedir = dir.join("exe");
        std::fs::create_dir_all(&exedir).expect("exe dir");
        let bundled = dir.join("kryprobe-bpf");
        std::fs::create_dir_all(&bundled).expect("bundled dir");
        std::fs::write(bundled.join("spine.bpf.o"), b"obj").expect("write bundled");
        // Env tier first, then exe tier (CWD tier depends on runner CWD).
        let found = bpf_object_candidates(env_file.to_str(), Some(&exedir), false);
        assert_eq!(found.first(), Some(&env_file));
        assert_eq!(
            found.get(1),
            Some(&exedir.join("../kryprobe-bpf/spine.bpf.o"))
        );
        // Empty env is ignored.
        let found = bpf_object_candidates(Some(""), Some(&exedir), false);
        assert_eq!(
            found.first(),
            Some(&exedir.join("../kryprobe-bpf/spine.bpf.o"))
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bpf_object_candidates_elevated_drops_env_tier() {
        // H-SEC-01 scenario 3: elevated selftest never loads an
        // env-steered object.
        let dir = scratch("cand-elev");
        let env_file = dir.join("custom-spine.o");
        std::fs::write(&env_file, b"obj").expect("write env file");
        let exedir = dir.join("exe");
        std::fs::create_dir_all(&exedir).expect("exe dir");
        let found = bpf_object_candidates(env_file.to_str(), Some(&exedir), true);
        assert!(
            !found.contains(&env_file),
            "elevated must not honor KRYPROBE_BPF_OBJ: {found:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sibling_candidates_elevated_drops_env_tier() {
        // L-SEC-04: elevated selftest never executes an env-steered helper.
        let dir = scratch("sib-elev");
        let env_file = dir.join("evil-helper");
        std::fs::write(&env_file, b"x").expect("write env file");
        let found = sibling_candidates(
            "helper",
            env_file.to_str(),
            Some(Path::new("/exe/dir")),
            true,
        );
        assert!(
            !found.contains(&env_file),
            "elevated must not honor helper env override: {found:?}"
        );
        // Unelevated keeps the documented env-first order.
        let found = sibling_candidates(
            "helper",
            env_file.to_str(),
            Some(Path::new("/exe/dir")),
            false,
        );
        assert_eq!(found.first(), Some(&env_file));
        std::fs::remove_dir_all(&dir).ok();
    }
}
