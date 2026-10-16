// SPDX-License-Identifier: GPL-3.0-or-later
//! T10: privileged CLI lane (`#[ignore]`, run via `cargo xtask test bpf`).

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use std::fmt;
use std::path::PathBuf;
use std::process::Command;

fn kryprobe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kryprobe"))
}

/// `--calls` for the `selftest bpf` probe: the lane exports its own
/// value via `KRYPROBE_BPF_CALLS` (single source); bare `xtask test
/// bpf` runs default to 20000.
fn parse_calls(var: Option<&str>) -> u64 {
    let calls: u64 = var
        .unwrap_or("20000")
        .parse()
        .expect("KRYPROBE_BPF_CALLS u64");
    assert!(calls > 0, "KRYPROBE_BPF_CALLS must be positive");
    assert!(
        calls <= u64::MAX / 2,
        "KRYPROBE_BPF_CALLS exceeds u64::MAX/2"
    );
    calls
}

/// P7/T12 lane policy, mirrored by `scripts/sudo_lane.py::partial_receipt`:
/// an exit-3 `selftest bpf` run is an accounted partial (not a
/// defect) iff stderr carries exactly one `reconcile: partial`
/// marker, one partial line, and one entries line whose counts
/// re-derive full accounting against `calls`. Pressure-only: drop
/// and trunc are anomaly buckets and never accepted. Returns true
/// missing (ground truth minus delivered). The printed
/// partial-line number is arm-dependent; only its shape, u64 range,
/// and agreement with the entries line are checked.
fn accounted_partial(stderr: &str, calls: u64) -> Result<u64, &'static str> {
    if stderr.contains('\r') {
        return Err("carriage return");
    }
    if stderr.contains('\u{fffd}') {
        return Err("replacement character");
    }
    let markers: Vec<&str> = stderr
        .lines()
        .filter(|line| line.starts_with("reconcile:"))
        .collect();
    if markers != ["reconcile: partial"] {
        return Err("reconcile marker");
    }
    let partials: Vec<&str> = stderr
        .lines()
        .filter(|line| line.starts_with("selftest bpf: partial ("))
        .collect();
    if partials.len() != 1 {
        return Err("partial line count");
    }
    let inner = partials[0]
        .strip_prefix("selftest bpf: partial (")
        .and_then(|rest| rest.strip_suffix(')'))
        .ok_or("partial line shape")?;
    let (printed, rest) = inner.split_once(' ').ok_or("partial line shape")?;
    if printed.is_empty() || !printed.bytes().all(|b| b.is_ascii_digit()) {
        return Err("partial line shape");
    }
    let _: u64 = printed.parse().map_err(|_| "partial line shape")?;
    let receipts = rest.strip_prefix("missing; ").ok_or("partial line shape")?;
    let prounds =
        parse_kv_line(receipts, &["ring", "drop", "trunc", "queue"]).ok_or("partial line shape")?;
    let entries: Vec<&str> = stderr
        .lines()
        .filter(|line| line.starts_with("selftest bpf: entries="))
        .collect();
    if entries.len() != 1 {
        return Err("entries line count");
    }
    let counts = entries[0]
        .strip_prefix("selftest bpf: ")
        .and_then(|rest| {
            parse_kv_line(
                rest,
                &[
                    "entries", "returns", "received", "ring", "drop", "trunc", "queue",
                ],
            )
        })
        .ok_or("entries line shape")?;
    let [e, r, v, ring, drop, trunc, queue] = counts[..] else {
        return Err("entries line shape");
    };
    if prounds[..] != [ring, drop, trunc, queue] {
        return Err("receipt mismatch");
    }
    if drop != 0 || trunc != 0 {
        return Err("anomaly receipts");
    }
    if (e as u128) + (r as u128) != v as u128 {
        return Err("kind sum");
    }
    if e > calls || r > calls {
        return Err("over-count");
    }
    if e == 0 || r == 0 {
        return Err("delivery floor");
    }
    if (v as u128) + (ring as u128) + (drop as u128) + (trunc as u128) + (queue as u128)
        != 2 * (calls as u128)
    {
        return Err("accounting equation");
    }
    if (ring as u128) + (queue as u128) == 0 {
        return Err("vacuous partial");
    }
    Ok(2 * calls - v)
}

/// Strict `k=v` space-joined tail: exact keys in order, ASCII-digit
/// u64 values, no extras. Returns the values in key order.
fn parse_kv_line(line: &str, keys: &[&str]) -> Option<Vec<u64>> {
    let mut out = Vec::with_capacity(keys.len());
    for (i, pair) in line.split(' ').enumerate() {
        let (key, value) = pair.split_once('=')?;
        if key != *keys.get(i)? {
            return None;
        }
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        out.push(value.parse::<u64>().ok()?);
    }
    (out.len() == keys.len()).then_some(out)
}

/// `serde_json::Value` that rejects duplicate object keys at every
/// level (plain `Value` keeps the last, which smuggles forged
/// terminal fields). serde's tokenizer decodes keys first, so
/// escaped spellings hide nothing; array repeats stay legal.
struct NoDup(serde_json::Value);

impl<'de> serde::Deserialize<'de> for NoDup {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NoDupVisitor;
        impl<'de> Visitor<'de> for NoDupVisitor {
            type Value = NoDup;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<NoDup, E> {
                Ok(NoDup(serde_json::Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<NoDup, E> {
                Ok(NoDup(serde_json::Value::Number(v.into())))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<NoDup, E> {
                Ok(NoDup(serde_json::Value::Number(v.into())))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<NoDup, E> {
                match serde_json::Number::from_f64(v) {
                    Some(n) => Ok(NoDup(serde_json::Value::Number(n))),
                    // Unreachable (serde rejects non-finite at tokenize),
                    // but Null must never stand in for a number.
                    None => Err(de::Error::custom("non-finite float")),
                }
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<NoDup, E> {
                Ok(NoDup(serde_json::Value::String(v.to_owned())))
            }
            fn visit_none<E: de::Error>(self) -> Result<NoDup, E> {
                Ok(NoDup(serde_json::Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<NoDup, E> {
                Ok(NoDup(serde_json::Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<NoDup, A::Error> {
                let mut out = Vec::new();
                while let Some(item) = seq.next_element::<NoDup>()? {
                    out.push(item.0);
                }
                Ok(NoDup(serde_json::Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<NoDup, A::Error> {
                let mut obj = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if obj.contains_key(&key) {
                        return Err(de::Error::custom(format!("duplicate key `{key}`")));
                    }
                    obj.insert(key, map.next_value::<NoDup>()?.0);
                }
                Ok(NoDup(serde_json::Value::Object(obj)))
            }
        }
        deserializer.deserialize_any(NoDupVisitor)
    }
}

fn parse_line(line: &str) -> serde_json::Value {
    serde_json::from_str::<NoDup>(line).expect("jsonl").0
}

fn session_end(stdout: &str) -> serde_json::Value {
    let ends: Vec<serde_json::Value> = stdout
        .lines()
        .map(parse_line)
        .filter(|record| record["kind"] == "session_end")
        .collect();
    assert_eq!(ends.len(), 1, "exactly one session_end: {stdout}");
    ends.into_iter().next().expect("session_end record")
}

/// Terminal-record agreement for one exit arm: the expected session
/// verdict, a fixture exit of exactly 0, and an explicit null
/// signal. Missing fields fail (absent is not null).
fn check_session_end(end: &serde_json::Value, verdict: &str, stdout: &str) {
    assert_eq!(end["payload"]["verdict"], verdict, "stdout: {stdout}");
    assert_eq!(end["payload"]["child_exit_code"], 0, "stdout: {stdout}");
    assert!(
        end["payload"]
            .get("child_signal")
            .is_some_and(|signal| signal.is_null()),
        "stdout: {stdout}"
    );
}

#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn selftest_bpf_clean_partial_or_denied() {
    let calls = match std::env::var_os("KRYPROBE_BPF_CALLS") {
        None => parse_calls(None),
        Some(raw) => parse_calls(Some(
            raw.to_str().expect("KRYPROBE_BPF_CALLS must be UTF-8"),
        )),
    };
    let output = Command::new(kryprobe())
        .args(["selftest", "bpf", "--calls", &calls.to_string()])
        .output()
        .expect("spawn");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf-8");
    match output.status.code() {
        Some(0) => {
            assert!(stderr.contains("reconcile: clean"), "stderr: {stderr}");
            // The owned fixture exited 0: session_end must say so.
            let stdout = String::from_utf8(output.stdout).expect("stdout utf-8");
            let end = session_end(&stdout);
            check_session_end(&end, "OBSERVED", &stdout);
        }
        Some(3) => {
            let missing = accounted_partial(&stderr, calls).expect("accounted partial");
            // Exit 3, marker, and session verdict come from one
            // producer match arm: session_end must agree.
            let stdout = String::from_utf8(output.stdout).expect("stdout utf-8");
            let end = session_end(&stdout);
            check_session_end(&end, "PARTIAL", &stdout);
            // Echo the child output so the lane re-verifies the same
            // accounting from this body log (sudo_lane SELFTEST_BPF_E2E;
            // the session cross-check needs the stdout JSONL too).
            eprintln!("selftest bpf: accounted partial ({missing} missing); child output follows:");
            eprintln!("{stderr}");
            eprintln!("{stdout}");
        }
        Some(4) => {
            assert!(stderr.contains("Denied{"), "stderr: {stderr}");
            eprintln!("SKIP: selftest BPF denied: {stderr}");
        }
        Some(code) => panic!("unexpected exit {code}: {stderr}"),
        None => panic!("killed by signal: {stderr}"),
    }
}

#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn selftest_token_smoke_needs_root() {
    // SAFETY: idempotent getter.
    if unsafe { libc::geteuid() } == 0 {
        println!("SKIP: non-root proof needs euid != 0 (root path runs in T12)");
        return;
    }
    let output = Command::new(kryprobe())
        .args(["selftest", "token-smoke"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(4));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf-8");
    assert!(stderr.contains("needs root"), "stderr: {stderr}");
}

#[cfg(test)]
mod lane_policy_tests {
    use super::{accounted_partial, check_session_end, parse_calls, session_end};

    /// [entries, returns, received, ring, drop, trunc, queue, printed_missing].
    fn output(c: [u64; 8]) -> String {
        let [e, r, v, ring, drop, trunc, queue, printed] = c;
        format!(
            "selftest bpf: partial ({printed} missing; ring={ring} drop={drop} trunc={trunc} queue={queue})\n\
             selftest bpf: entries={e} returns={r} received={v} ring={ring} drop={drop} trunc={trunc} queue={queue}\n\
             reconcile: partial\n"
        )
    }

    #[test]
    fn oct13_shape_accepts() {
        let stderr = output([19707, 19712, 39419, 581, 0, 0, 0, 581]);
        assert_eq!(accounted_partial(&stderr, 20000), Ok(581));
    }

    #[test]
    fn queue_receipted_partial_accepts() {
        // The ledger excludes queue drops: printed 10 is the
        // remainder while all 20 missing records are receipted.
        let stderr = output([90, 90, 180, 10, 0, 0, 10, 10]);
        assert_eq!(accounted_partial(&stderr, 100), Ok(20));
    }

    #[test]
    fn silent_loss_rejects() {
        // 6 records gone, 3 receipted: the printed remainder (3)
        // numerically matches ring but the equation fails.
        let stderr = output([97, 97, 194, 3, 0, 0, 0, 3]);
        assert_eq!(accounted_partial(&stderr, 100), Err("accounting equation"));
    }

    #[test]
    fn defects_reject() {
        // otherwise-valid: only the over-count rejects (mutant-killing;
        // verified by disabling each half and observing acceptance)
        assert_eq!(
            accounted_partial(&output([101, 97, 198, 2, 0, 0, 0, 2]), 100),
            Err("over-count")
        );
        assert_eq!(
            accounted_partial(&output([97, 101, 198, 2, 0, 0, 0, 2]), 100),
            Err("over-count")
        );
        assert_eq!(
            accounted_partial(&output([90, 89, 180, 10, 0, 0, 10, 10]), 100),
            Err("kind sum")
        );
        assert_eq!(
            accounted_partial(&output([100, 100, 200, 0, 0, 0, 0, 0]), 100),
            Err("vacuous partial")
        );
        assert_eq!(
            accounted_partial(&output([90, 90, 180, 9, 0, 0, 0, 11]), 100),
            Err("accounting equation")
        );
    }

    #[test]
    fn malformed_shapes_reject() {
        let base = output([9, 9, 18, 1, 0, 0, 1, 2]);
        assert_eq!(accounted_partial(&base, 10), Ok(2));
        let bad = [
            format!("{base}reconcile: partial\n"),
            base.replace("reconcile: partial\n", "reconcile: clean\n"),
            base.replace("reconcile: partial\n", "reconcile: defect\n"),
            format!("{base}reconcile: defect (corrupt)\n"),
            format!("{base}reconcile:defect\n"),
            base.replace("reconcile: partial\n", ""),
            format!(
                "{base}selftest bpf: entries=9 returns=9 received=18 ring=1 drop=0 trunc=0 queue=1\n"
            ),
            format!(
                "{base}selftest bpf: entries=0 returns=0 received=0 ring=0 drop=0 trunc=0 queue=0 CORRUPT\n"
            ),
            format!("{base}selftest bpf: partial (bogus)\n"),
            base.replace("(2 missing;", "(18446744073709551616 missing;"),
            base.replace("entries=9", &format!("entries={}", "9".repeat(5000))),
            base.replace("entries=9", "entries=\u{ff19}"),
            base.replace('\n', "\r\n"),
            format!("{base}\u{fffd}\n"),
        ];
        for stderr in &bad {
            assert!(accounted_partial(stderr, 10).is_err(), "stderr: {stderr}");
        }
    }

    #[test]
    fn anomaly_receipts_reject() {
        // drop/trunc are anomaly buckets, never pressure receipts.
        assert_eq!(
            accounted_partial(&output([99, 99, 198, 1, 1, 0, 0, 2]), 100),
            Err("anomaly receipts")
        );
        assert_eq!(
            accounted_partial(&output([99, 99, 198, 1, 0, 1, 0, 2]), 100),
            Err("anomaly receipts")
        );
        assert_eq!(
            accounted_partial(&output([0, 0, 0, 0, 40000, 0, 0, 40000]), 20000),
            Err("anomaly receipts")
        );
    }

    #[test]
    fn delivery_floor_rejects() {
        assert_eq!(
            accounted_partial(&output([0, 10, 10, 10, 0, 0, 0, 10]), 10),
            Err("delivery floor")
        );
        assert_eq!(
            accounted_partial(&output([10, 0, 10, 10, 0, 0, 0, 10]), 10),
            Err("delivery floor")
        );
    }

    #[test]
    fn receipt_mismatch_rejects() {
        // both lines print the same producer fields; the entries
        // side still satisfies the equation, isolating the cross-check
        let stderr = output([9, 9, 18, 1, 0, 0, 1, 2])
            .replacen("ring=1", "ring=2", 1)
            .replacen("queue=1", "queue=0", 1);
        assert_eq!(accounted_partial(&stderr, 10), Err("receipt mismatch"));
    }

    #[test]
    fn calls_default_and_value() {
        assert_eq!(parse_calls(None), 20000);
        assert_eq!(parse_calls(Some("5000")), 5000);
        assert_eq!(
            parse_calls(Some("9223372036854775807")),
            9223372036854775807
        );
    }

    #[test]
    #[should_panic(expected = "u64::MAX/2")]
    fn calls_above_half_max_panics() {
        parse_calls(Some("9223372036854775808"));
    }

    #[test]
    #[should_panic(expected = "positive")]
    fn calls_zero_panics() {
        parse_calls(Some("0"));
    }

    #[test]
    #[should_panic(expected = "u64")]
    fn calls_non_numeric_panics() {
        parse_calls(Some("abc"));
    }

    fn session_stdout(payload: &str) -> String {
        format!(
            "{{\"kind\":\"session_start\"}}\n{{\"kind\":\"session_end\",\"payload\":{payload}}}\n"
        )
    }

    const GOOD_PAYLOAD: &str = r#"{"verdict":"PARTIAL","child_exit_code":0,"child_signal":null}"#;

    #[test]
    fn session_end_unique_record_checks() {
        let stdout = session_stdout(GOOD_PAYLOAD);
        let end = session_end(&stdout);
        check_session_end(&end, "PARTIAL", &stdout);
    }

    #[test]
    #[should_panic(expected = "exactly one session_end")]
    fn session_end_duplicate_panics() {
        let one = session_stdout(GOOD_PAYLOAD);
        session_end(&(one.clone() + &one));
    }

    #[test]
    #[should_panic(expected = "exactly one session_end")]
    fn session_end_missing_panics() {
        session_end("{\"kind\":\"session_start\"}\n");
    }

    #[test]
    #[should_panic(expected = "duplicate key")]
    fn session_end_duplicate_field_panics() {
        let stdout = session_stdout(
            r#"{"verdict":"PARTIAL","child_exit_code":1,"child_exit_code":0,"child_signal":null}"#,
        );
        session_end(&stdout);
    }

    #[test]
    #[should_panic(expected = "duplicate key")]
    fn session_end_duplicate_kind_panics() {
        session_end(
            "{\"kind\":\"session_end\",\"kind\":\"noise\",\"payload\":{\"verdict\":\"PARTIAL\",\
             \"child_exit_code\":0,\"child_signal\":null}}\n",
        );
    }

    #[test]
    #[should_panic(expected = "duplicate key")]
    fn session_end_escaped_duplicate_key_panics() {
        // serde decodes keys before visiting: the escape hides nothing
        let stdout = session_stdout(
            r#"{"verdict":"PARTIAL","child_exit_code":1,"child_\u0065xit_code":0,"child_signal":null}"#,
        );
        session_end(&stdout);
    }

    #[test]
    fn session_end_repeated_array_values_pass() {
        let stdout = session_stdout(
            r#"{"verdict":"PARTIAL","child_exit_code":0,"child_signal":null,"ids":[1,1]}"#,
        );
        let end = session_end(&stdout);
        check_session_end(&end, "PARTIAL", &stdout);
    }

    #[test]
    #[should_panic(expected = "stdout: ")]
    fn session_check_wrong_verdict_panics() {
        let stdout =
            session_stdout(r#"{"verdict":"FAILED","child_exit_code":0,"child_signal":null}"#);
        let end = session_end(&stdout);
        check_session_end(&end, "PARTIAL", &stdout);
    }

    #[test]
    #[should_panic(expected = "stdout: ")]
    fn session_check_nonzero_exit_panics() {
        let stdout =
            session_stdout(r#"{"verdict":"PARTIAL","child_exit_code":1,"child_signal":null}"#);
        let end = session_end(&stdout);
        check_session_end(&end, "PARTIAL", &stdout);
    }

    #[test]
    #[should_panic(expected = "stdout: ")]
    fn session_check_bool_exit_panics() {
        let stdout =
            session_stdout(r#"{"verdict":"PARTIAL","child_exit_code":false,"child_signal":null}"#);
        let end = session_end(&stdout);
        check_session_end(&end, "PARTIAL", &stdout);
    }

    #[test]
    #[should_panic(expected = "stdout: ")]
    fn session_check_float_exit_panics() {
        let stdout =
            session_stdout(r#"{"verdict":"PARTIAL","child_exit_code":0.0,"child_signal":null}"#);
        let end = session_end(&stdout);
        check_session_end(&end, "PARTIAL", &stdout);
    }

    #[test]
    #[should_panic(expected = "stdout: ")]
    fn session_check_signalled_panics() {
        let stdout =
            session_stdout(r#"{"verdict":"PARTIAL","child_exit_code":0,"child_signal":"TERM"}"#);
        let end = session_end(&stdout);
        check_session_end(&end, "PARTIAL", &stdout);
    }

    #[test]
    #[should_panic(expected = "stdout: ")]
    fn session_check_missing_signal_panics() {
        let stdout = session_stdout(r#"{"verdict":"PARTIAL","child_exit_code":0}"#);
        let end = session_end(&stdout);
        check_session_end(&end, "PARTIAL", &stdout);
    }
}
