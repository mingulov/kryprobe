// SPDX-License-Identifier: GPL-3.0-or-later
//! Best-effort kernel-stack symbolizer over `/proc/kallsyms` text (K5 Task 4).
//!
//! [`symbolize`] is pure over its inputs (fixture-tested, no filesystem
//! touch); [`read_kallsyms`] is the only reader, and it degrades to an
//! empty string on ANY read error (kptr_restrict, containers, missing
//! proc — symbolization stays best-effort, never a gate, never a decoder
//! failure). Unresolvable frames keep their raw `ip` with `sym: None`.
//!
//! [`SymTable`] is the shared parsed form: parse once per kallsyms read
//! and symbolize many row sets through [`symbolize_with`]. Per-row
//! [`symbolize`] calls re-parse + re-sort the whole map every time.
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

/// Kallsyms text parsed + sorted once, shared across many symbolize calls.
///
/// A live tick reads `/proc/kallsyms` once and decodes every who row
/// against the same table: parsing per row re-sorts ~10^5 entries per
/// row (2B-C2). The table borrows the text it was parsed from, so the
/// tick keeps the `String` alive for the tick's duration.
#[derive(Debug, Clone)]
pub struct SymTable<'a> {
    entries: Vec<(u64, &'a str)>,
}

/// Lifetime count of [`SymTable::parse`] calls in this process.
///
/// Observability hook for H-T3(1): a live session must parse exactly
/// one table per tick no matter how many who rows the tick carries,
/// and tests assert that by diffing this counter across a driven
/// session. One `Relaxed` increment per parse — noise next to an
/// O(K log K) parse+sort of ~10^5 entries.
static PARSE_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Lifetime [`SymTable::parse`] calls in this process (H-T3(1) hook).
#[must_use]
pub fn parse_calls() -> u64 {
    PARSE_CALLS.load(std::sync::atomic::Ordering::Relaxed)
}

impl<'a> SymTable<'a> {
    /// Parse `kallsyms` text (`addr type name` lines) into a sorted table.
    ///
    /// Same skip rules as [`symbolize`]: unparseable lines (fewer than 3
    /// fields, non-hex address) and zero addresses (kptr_restrict) never
    /// become floors.
    #[must_use]
    pub fn parse(kallsyms: &'a str) -> Self {
        PARSE_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
        Self { entries }
    }

    /// Nearest-below floor for `ip`: the symbol with the greatest start
    /// address `<= ip`, or `None` when no floor exists below the IP.
    #[must_use]
    pub fn floor(&self, ip: u64) -> Option<&str> {
        let n = self.entries.partition_point(|entry| entry.0 <= ip);
        if n == 0 {
            None
        } else {
            Some(self.entries[n - 1].1)
        }
    }
}

/// Symbolize `ips` against a pre-parsed [`SymTable`] (parse once per
/// kallsyms read, share across rows).
#[must_use]
pub fn symbolize_with(ips: &[u64], table: &SymTable) -> Vec<Frame> {
    ips.iter()
        .map(|ip| Frame {
            ip: *ip,
            sym: table.floor(*ip).map(str::to_owned),
        })
        .collect()
}

/// Symbolize `ips` against `kallsyms` text (`addr type name` lines).
///
/// Unparseable lines (fewer than 3 fields, non-hex address) and zero
/// addresses are skipped; the survivors sort by address and each IP
/// binary-searches its nearest-below floor. Empty/unparseable input
/// yields all-`None` frames (one per IP, IPs echoed).
///
/// Parses on every call; callers symbolizing many row sets against one
/// read should parse a [`SymTable`] once and use [`symbolize_with`].
#[must_use]
pub fn symbolize(ips: &[u64], kallsyms: &str) -> Vec<Frame> {
    symbolize_with(ips, &SymTable::parse(kallsyms))
}

/// Read `/proc/kallsyms` to a string; ANY read error yields an empty
/// string (best-effort, never `Err` — callers symbolize against it and
/// get all-`None` frames, raw IPs kept).
#[must_use]
pub fn read_kallsyms() -> String {
    std::fs::read_to_string("/proc/kallsyms").unwrap_or_default()
}
