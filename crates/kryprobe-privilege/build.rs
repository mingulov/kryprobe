// SPDX-License-Identifier: GPL-3.0-or-later
//! Build-time pinned BPF-object digests (H-SEC-01).
//!
//! `KRYPROBE_PIN_DIGESTS` (comma-separated lowercase hex sha256,
//! baked by release packaging, see `docs/deployment.md`) pins the
//! release object digests into the binary. Unset/empty = dev build:
//! the pin check is skipped with a runtime warning (env/CWD tiers
//! are still refused when elevated).

fn main() {
    println!("cargo::rerun-if-env-changed=KRYPROBE_PIN_DIGESTS");
    println!("cargo::rerun-if-env-changed=KRYPROBE_REQUIRE_PINS");
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
    // G6 fail-secure opt-in (fail-open audit): release packaging
    // sets `KRYPROBE_REQUIRE_PINS=1`, so a missing pin set fails the
    // build instead of shipping a silently unpinned binary. A bare
    // release build without pins warns loudly instead of failing, so
    // local `cargo build --release` keeps working.
    if digests.is_empty() {
        assert!(
            std::env::var("KRYPROBE_REQUIRE_PINS").unwrap_or_default() != "1",
            "KRYPROBE_REQUIRE_PINS=1 but KRYPROBE_PIN_DIGESTS is empty: \
             refusing to bake an unpinned binary",
        );
        if std::env::var("PROFILE").as_deref() == Ok("release") {
            println!(
                "cargo::warning=empty KRYPROBE_PIN_DIGESTS: this release binary will \
                 SKIP BPF object pin verification (set KRYPROBE_PIN_DIGESTS to pin it)"
            );
        }
    }
    let list = digests
        .iter()
        .map(|d| format!("\"{d}\""))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        out.join("pinned_digests.rs"),
        format!(
            "/// Baked release-object sha256 pins (empty in dev builds: pin check skipped).\npub(crate) const PINNED_DIGESTS: &[&str] = &[{list}];\n"
        ),
    )
    .expect("write pinned digests");
}
