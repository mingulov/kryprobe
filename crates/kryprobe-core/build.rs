// SPDX-License-Identifier: GPL-3.0-or-later
//! Declares the `kani` cfg so `#[cfg(kani)]` proof harnesses (audit #17)
//! don't trip `unexpected_cfgs` under `-D warnings`. Only `cargo kani`
//! ever sets the cfg; normal builds never compile the proofs.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(kani)");
}
