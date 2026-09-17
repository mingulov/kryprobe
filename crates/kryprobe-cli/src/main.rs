// SPDX-License-Identifier: GPL-3.0-or-later
//! `kryprobe` binary: thin argv/exit-code shell over the library.

use std::io::Write;

fn main() {
    let argv: Vec<String> = std::env::args_os()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let code = kryprobe_cli::run(
        &argv,
        &mut std::io::stdout().lock() as &mut dyn Write,
        &mut std::io::stderr().lock() as &mut dyn Write,
    );
    std::process::exit(code);
}
