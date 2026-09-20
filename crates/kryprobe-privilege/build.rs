// SPDX-License-Identifier: GPL-3.0-or-later
//! Build-time pinned BPF-object digests (H-SEC-01).
//!
//! `KRYPROBE_PIN_DIGESTS` (comma-separated lowercase hex sha256,
//! normally written by the `xtask package` lane) bakes the release
//! object pins into the binary. Unset/empty = dev build: the pin
//! check is skipped (env/CWD tiers are still refused when elevated).

fn main() {
    println!("cargo::rerun-if-env-changed=KRYPROBE_PIN_DIGESTS");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let digests: Vec<String> = std::env::var("KRYPROBE_PIN_DIGESTS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    for digest in &digests {
        assert!(
            digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "KRYPROBE_PIN_DIGESTS entries must be 64 lowercase hex chars, got {digest:?}"
        );
    }
    let list = digests
        .iter()
        .map(|d| format!("\"{d}\""))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        out.join("pinned_digests.rs"),
        format!("pub const PINNED_DIGESTS: &[&str] = &[{list}];\n"),
    )
    .expect("write pinned digests");
}
