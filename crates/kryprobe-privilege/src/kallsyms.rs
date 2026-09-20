// SPDX-License-Identifier: GPL-3.0-or-later
//! Best-effort kernel-stack symbolizer over `/proc/kallsyms` text (K5 Task 4).
//!
//! [`symbolize`] is pure over its inputs (fixture-tested, no filesystem
//! touch); [`read_kallsyms`] is the only reader, and it degrades to an
//! empty string on ANY read error (kptr_restrict, containers, missing
//! proc — symbolization stays best-effort, never a gate, never a decoder
//! failure). Unresolvable frames keep their raw `ip` with `sym: None`.
//!
//! Match rule: nearest-below — each IP resolves to the symbol with the
//! greatest start address `<= ip` (an IP below the first entry has no
//! floor, hence `None`). Zero addresses are SKIPPED at parse: with
//! `kptr_restrict` hiding addresses every line reads `00000000...`, and
//! a zero floor would misattribute every IP — spec §2.2 pins hidden
//! addrs to `sym: null`.

/// One symbolized frame: the raw IP plus its nearest-below symbol (or
/// `None` when unresolvable — empty/unparseable map, hidden addresses,
/// or no floor below the IP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Raw kernel instruction pointer (always echoed, never dropped).
    pub ip: u64,
    /// Nearest-below symbol name (`None` when unresolvable).
    pub sym: Option<String>,
}

/// Symbolize `ips` against `kallsyms` text (`addr type name` lines).
///
/// Unparseable lines (fewer than 3 fields, non-hex address) and zero
/// addresses are skipped; the survivors sort by address and each IP
/// binary-searches its nearest-below floor. Empty/unparseable input
/// yields all-`None` frames (one per IP, IPs echoed).
#[must_use]
pub fn symbolize(ips: &[u64], kallsyms: &str) -> Vec<Frame> {
    let mut entries: Vec<(u64, &str)> = Vec::new();
    for line in kallsyms.lines() {
        let mut fields = line.split_whitespace();
        let (Some(addr), Some(_ty), Some(name)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Ok(start) = u64::from_str_radix(addr, 16) else {
            continue;
        };
        if start == 0 {
            // Hidden by kptr_restrict: never a floor (see module docs).
            continue;
        }
        entries.push((start, name));
    }
    entries.sort_by_key(|entry| entry.0);
    ips.iter()
        .map(|ip| {
            let floor = entries.partition_point(|entry| entry.0 <= *ip);
            Frame {
                ip: *ip,
                sym: if floor == 0 {
                    None
                } else {
                    Some(entries[floor - 1].1.to_owned())
                },
            }
        })
        .collect()
}

/// Read `/proc/kallsyms` to a string; ANY read error yields an empty
/// string (best-effort, never `Err` — callers symbolize against it and
/// get all-`None` frames, raw IPs kept).
#[must_use]
pub fn read_kallsyms() -> String {
    std::fs::read_to_string("/proc/kallsyms").unwrap_or_default()
}
