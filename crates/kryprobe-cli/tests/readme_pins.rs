// SPDX-License-Identifier: GPL-3.0-or-later
//! README pins (3B-H2): the exit-code table is the `USAGE` family
//! verbatim — README edits and CLI edits cannot drift apart.

/// The kp2 exit family, mirrored from `args::USAGE`.
const EXITS: &[(u8, &str)] = &[
    (0, "clean/ok"),
    (1, "internal failure"),
    (2, "usage/invalid input"),
    (3, "inconclusive/PARTIAL"),
    (4, "environment-unusable"),
    (10, "policy violation"),
];

fn readme() -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../README.md");
    std::fs::read_to_string(&path).expect("README reads")
}

#[test]
fn readme_pins_usage_exits() {
    let usage = kryprobe_cli::args::USAGE;
    let readme = readme();
    // The pin table itself tracks USAGE (CLI side cannot drift).
    for (code, meaning) in EXITS {
        assert!(
            usage.contains(&format!("{code} {meaning}")),
            "USAGE must carry exit {code} ({meaning})"
        );
    }
    // README carries every (code, meaning) pair as a table row.
    for line in readme.lines().filter(|line| line.starts_with('|')) {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 4 {
            continue;
        }
        if let Ok(code) = cells[1].parse::<u8>() {
            let want = EXITS
                .iter()
                .find(|(c, _)| *c == code)
                .unwrap_or_else(|| panic!("README exit row {code} unknown to the pin table"));
            assert_eq!(cells[2], want.1, "README meaning for exit {code}");
        }
    }
    for (code, meaning) in EXITS {
        assert!(
            readme.lines().any(|line| {
                line.starts_with('|')
                    && line.contains(&format!("| {code} "))
                    && line.contains(meaning)
            }),
            "README must table exit {code} ({meaning})"
        );
    }
}
