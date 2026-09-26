// SPDX-License-Identifier: GPL-3.0-or-later
//! Build-time pinned BPF-object digests (H-SEC-01).
//!
//! Release packaging sets `KRYPROBE_PIN_OBJECTS` to comma-separated
//! `object-name=sha256` pairs for both supported profiles. Legacy
//! `KRYPROBE_PIN_DIGESTS` builds retain their flat allowlist, but do
//! not qualify as profile-bound releases. Both empty = dev build.

fn main() {
    println!("cargo::rerun-if-env-changed=KRYPROBE_PIN_DIGESTS");
    println!("cargo::rerun-if-env-changed=KRYPROBE_PIN_OBJECTS");
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
    let mut objects = std::collections::BTreeMap::new();
    for entry in std::env::var("KRYPROBE_PIN_OBJECTS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let (name, digest) = entry
            .split_once('=')
            .expect("KRYPROBE_PIN_OBJECTS entries must be object-name=sha256");
        let name = name.trim();
        assert!(
            matches!(name, "kcrypto.bpf.o" | "kcrypto-lifecycle.bpf.o"),
            "KRYPROBE_PIN_OBJECTS contains unknown object {name:?}"
        );
        let digest = digest.trim().to_lowercase();
        assert!(
            digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "KRYPROBE_PIN_OBJECTS digest must be 64 hex chars, got {digest:?}"
        );
        assert!(
            objects.insert(name.to_owned(), digest).is_none(),
            "KRYPROBE_PIN_OBJECTS repeats object {name:?}"
        );
    }
    assert!(
        objects.is_empty() || objects.len() == 2,
        "KRYPROBE_PIN_OBJECTS must bind both kcrypto profiles"
    );
    assert!(
        objects.is_empty() || digests.is_empty(),
        "set only one of KRYPROBE_PIN_OBJECTS and legacy KRYPROBE_PIN_DIGESTS"
    );
    // G6 fail-secure opt-in (fail-open audit): release packaging
    // sets `KRYPROBE_REQUIRE_PINS=1`, so a missing pin set fails the
    // build instead of shipping a silently unpinned binary. A bare
    // release build without pins warns loudly instead of failing, so
    // local `cargo build --release` keeps working.
    if digests.is_empty() && objects.is_empty() {
        assert!(
            std::env::var("KRYPROBE_REQUIRE_PINS").unwrap_or_default() != "1",
            "KRYPROBE_REQUIRE_PINS=1 but both pin sets are empty: \
             refusing to bake an unpinned binary",
        );
        if std::env::var("PROFILE").as_deref() == Ok("release") {
            println!(
                "cargo::warning=empty BPF pins: this release binary will \
                 SKIP object pin verification (set KRYPROBE_PIN_OBJECTS to pin it)"
            );
        }
    }
    let list = digests
        .iter()
        .map(|d| format!("\"{d}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let objects = objects
        .iter()
        .map(|(name, digest)| format!("({name:?}, {digest:?})"))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        out.join("pinned_digests.rs"),
        format!(
            "/// Legacy flat pins (empty in dev or profile-bound builds).\npub(crate) const PINNED_DIGESTS: &[&str] = &[{list}];\n\
             /// Release object names bound to sha256 digests.\npub(crate) const PINNED_OBJECTS: &[(&str, &str)] = &[{objects}];\n"
        ),
    )
    .expect("write pinned digests");
}
