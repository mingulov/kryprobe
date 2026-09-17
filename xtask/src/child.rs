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

/// Same as [`run_child`] but with an explicit working directory.
pub(crate) fn run_child_in(dir: &Path, program: &str, args: &[&str]) -> i32 {
    let mut rendered = String::from(program);
    for arg in args {
        rendered.push(' ');
        rendered.push_str(arg);
    }
    println!("+ cd {} && {rendered}", dir.display());
    run_child_spawn(program, args, Some(dir))
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
