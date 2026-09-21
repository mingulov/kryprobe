// SPDX-License-Identifier: GPL-3.0-or-later
//! xtask child-process runner: print argv, spawn, propagate exit code.

use std::path::Path;
use std::process::Command;

pub(crate) fn run_child(program: &str, args: &[&str]) -> i32 {
    let mut rendered = String::from(program);
    for arg in args {
        rendered.push(' ');
        rendered.push_str(arg);
    }
    println!("+ {rendered}");
    run_child_spawn(program, args, None)
}

/// Same as [`run_child`] but with an explicit working directory,
/// and kills the child after `timeout_secs`, returning `None`
/// (4B-L2: the bpf-linker hang flake must surface as a loud
/// timeout, never a stuck lane).
pub(crate) fn run_child_in_timeout(
    dir: &Path,
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Option<i32> {
    let mut rendered = String::from(program);
    for arg in args {
        rendered.push(' ');
        rendered.push_str(arg);
    }
    println!("+ cd {} && {rendered}", dir.display());
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.current_dir(dir);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            eprintln!("xtask: cannot run `{rendered}`: {err}");
            return Some(1);
        }
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Some(match status.code() {
                    Some(code) => code,
                    None => {
                        eprintln!("xtask: `{rendered}` terminated by signal");
                        1
                    }
                });
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    eprintln!("xtask: `{rendered}` exceeded {timeout_secs}s; killing");
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(err) => {
                eprintln!("xtask: cannot wait for `{rendered}`: {err}");
                return Some(1);
            }
        }
    }
}

fn run_child_spawn(program: &str, args: &[&str], dir: Option<&Path>) -> i32 {
    let rendered = std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some(dir) = dir {
        cmd.current_dir(dir);
    }
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            eprintln!("xtask: cannot run `{rendered}`: {err}");
            return 1;
        }
    };
    let status = match child.wait() {
        Ok(status) => status,
        Err(err) => {
            eprintln!("xtask: cannot wait for `{rendered}`: {err}");
            return 1;
        }
    };
    match status.code() {
        Some(code) => code,
        None => {
            eprintln!("xtask: `{rendered}` terminated by signal");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp() -> PathBuf {
        std::env::temp_dir()
    }

    #[test]
    fn timeout_returns_exit_for_fast_children() {
        assert_eq!(run_child_in_timeout(&tmp(), "true", &[], 30), Some(0));
        assert_eq!(run_child_in_timeout(&tmp(), "false", &[], 30), Some(1));
    }

    #[test]
    fn timeout_kills_hung_children() {
        // 4B-L2: a hung child yields None promptly (not after its own
        // lifetime) — the lane retries once, loudly, then fails.
        let start = std::time::Instant::now();
        assert_eq!(run_child_in_timeout(&tmp(), "sleep", &["30"], 1), None);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "kill is prompt"
        );
    }
}
