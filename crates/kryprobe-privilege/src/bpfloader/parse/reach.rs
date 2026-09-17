// SPDX-License-Identifier: GPL-3.0-or-later
//! Parse-time reachability gate: every insn must be reachable (T7c1 split).
//!
//! The kernel verifier rejects programs with unreachable instructions,
//! and dead `.text` functions (unreferenced compiler builtins the link
//! cannot GC) are exactly that. The build strips them, but the loader
//! re-checks every stream it parses and fails closed with the dead
//! function's name instead of a cryptic verifier log.

use super::{BpfInsn, bad};
use crate::bpfloader::LoaderError;

/// Opcode `LD | DW` (64-bit immediate load: occupies two slots).
const OP_LD_DW: u8 = 0x18;
/// Opcode `JMP | CALL` (helper or subprogram call).
const OP_CALL: u8 = 0x85;
/// Opcode `JMP | EXIT` (program return).
const OP_EXIT: u8 = 0x95;
/// Opcode `JMP32 | JA` (32-bit unconditional jump).
const OP_JA32: u8 = 0x06;

/// Assert every insn of one resolved stream is reachable from entry.
///
/// `funcs` maps stream indices to function names for error messages:
/// (name, start index), ascending. Unknown jump encodings, out-of-range
/// edges, fallthrough past the end, and unvisited insns are all errors.
pub(crate) fn check_reachable(
    name: &str,
    insns: &[BpfInsn],
    funcs: &[(String, usize)],
) -> Result<(), LoaderError> {
    if insns.is_empty() {
        return Err(bad(format!("{name} has no instructions")));
    }
    let n = insns.len();
    let mut visited = vec![false; n];
    let mut stack = vec![0usize];
    while let Some(i) = stack.pop() {
        if visited[i] {
            continue;
        }
        visited[i] = true;
        let insn = insns[i];
        if insn.code == OP_LD_DW {
            if i + 1 >= n {
                return Err(bad(format!("{name}: truncated ld_imm64 at {i}")));
            }
            // The tail slot belongs to the head: mark it and continue
            // past the pair (pushing i+1 would stall on the visited bit).
            visited[i + 1] = true;
            if i + 2 == n {
                return Err(bad(format!("{name}: insn {i} falls off the end")));
            }
            stack.push(i + 2);
            continue;
        }
        match (insn.code & 0x07, insn.code & 0xf0) {
            (0x05, 0x00) => push_target(name, &mut stack, n, i, i64::from(insn.off))?,
            (0x05, 0x10 | 0x20 | 0x30 | 0x40 | 0x50 | 0x60 | 0x70) => {
                push_fallthrough(name, &mut stack, n, i)?;
                push_target(name, &mut stack, n, i, i64::from(insn.off))?;
            }
            (0x05, 0x80) => {
                if insn.code != OP_CALL {
                    return Err(bad(format!(
                        "{name}: unknown jump opcode {:#x} at {i}",
                        insn.code
                    )));
                }
                match insn.dst_src >> 4 {
                    0 => push_fallthrough(name, &mut stack, n, i)?,
                    1 => {
                        push_fallthrough(name, &mut stack, n, i)?;
                        push_target(name, &mut stack, n, i, i64::from(insn.imm))?;
                    }
                    src => {
                        return Err(bad(format!("{name}: call with src_reg {src} at {i}")));
                    }
                }
            }
            (0x05, 0x90) => {
                if insn.code != OP_EXIT {
                    return Err(bad(format!(
                        "{name}: unknown jump opcode {:#x} at {i}",
                        insn.code
                    )));
                }
            }
            (0x05, _) => {
                return Err(bad(format!(
                    "{name}: unknown jump opcode {:#x} at {i}",
                    insn.code
                )));
            }
            (0x06, 0x00) => {
                if insn.code != OP_JA32 {
                    return Err(bad(format!(
                        "{name}: unknown jump32 opcode {:#x} at {i}",
                        insn.code
                    )));
                }
                push_target(name, &mut stack, n, i, i64::from(insn.imm))?;
            }
            (0x06, 0x10 | 0x20 | 0x30 | 0x40 | 0x50 | 0x60 | 0x70) => {
                push_fallthrough(name, &mut stack, n, i)?;
                push_target(name, &mut stack, n, i, i64::from(insn.off))?;
            }
            (0x06, _) => {
                return Err(bad(format!(
                    "{name}: unknown jump32 opcode {:#x} at {i}",
                    insn.code
                )));
            }
            _ => push_fallthrough(name, &mut stack, n, i)?,
        }
    }
    if let Some(i) = visited.iter().position(|v| !v) {
        return Err(bad(format!(
            "{name}: unreachable insn {i} (function '{}')",
            func_at(funcs, i)
        )));
    }
    Ok(())
}

fn push_fallthrough(
    name: &str,
    stack: &mut Vec<usize>,
    n: usize,
    i: usize,
) -> Result<(), LoaderError> {
    if i + 1 >= n {
        return Err(bad(format!("{name}: insn {i} falls off the end")));
    }
    stack.push(i + 1);
    Ok(())
}

fn push_target(
    name: &str,
    stack: &mut Vec<usize>,
    n: usize,
    i: usize,
    delta: i64,
) -> Result<(), LoaderError> {
    let target = i as i64 + 1 + delta;
    if target < 0 || target >= n as i64 {
        return Err(bad(format!(
            "{name}: jump target {target} out of range at {i}"
        )));
    }
    stack.push(target as usize);
    Ok(())
}

fn func_at(funcs: &[(String, usize)], i: usize) -> &str {
    funcs
        .iter()
        .rev()
        .find(|(_, start)| *start <= i)
        .map(|(name, _)| name.as_str())
        .unwrap_or("?")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(code: u8, dst_src: u8, off: i16, imm: i32) -> BpfInsn {
        BpfInsn {
            code,
            dst_src,
            off,
            imm,
        }
    }

    const EXIT: BpfInsn = BpfInsn {
        code: 0x95,
        dst_src: 0,
        off: 0,
        imm: 0,
    };

    #[test]
    fn straight_line_is_reachable() {
        let stream = vec![insn(0xb7, 0, 0, 0), EXIT];
        assert!(check_reachable("t", &stream, &[("t".to_owned(), 0)]).is_ok());
    }

    #[test]
    fn dead_tail_is_rejected_with_function() {
        let stream = vec![EXIT, EXIT];
        let funcs = vec![("emit".to_owned(), 0), ("dead".to_owned(), 1)];
        let err = check_reachable("t", &stream, &funcs).unwrap_err();
        assert!(err.to_string().contains("unreachable insn 1"), "{err}");
        assert!(err.to_string().contains("'dead'"), "{err}");
    }

    #[test]
    fn jump_over_code_is_rejected() {
        // ja +1 skips insn 1, which no edge reaches.
        let stream = vec![insn(0x05, 0, 1, 0), EXIT, EXIT];
        let err = check_reachable("t", &stream, &[("t".to_owned(), 0)]).unwrap_err();
        assert!(err.to_string().contains("unreachable insn 1"), "{err}");
    }

    #[test]
    fn subprogram_call_visits_both_paths() {
        // call +1 (pseudo) reaches 2 and falls through to 1.
        let stream = vec![insn(0x85, 0x10, 0, 1), EXIT, EXIT];
        assert!(check_reachable("t", &stream, &[("t".to_owned(), 0)]).is_ok());
    }

    #[test]
    fn helper_call_is_fallthrough_only() {
        let stream = vec![insn(0x85, 0, 0, 1), EXIT];
        assert!(check_reachable("t", &stream, &[("t".to_owned(), 0)]).is_ok());
    }

    #[test]
    fn ld_imm64_marks_both_slots() {
        let stream = vec![insn(0x18, 0, 0, 0), insn(0, 0, 0, 0), EXIT];
        assert!(check_reachable("t", &stream, &[("t".to_owned(), 0)]).is_ok());
    }

    #[test]
    fn bad_edges_fail_closed() {
        // Out-of-range jump.
        let stream = vec![insn(0x05, 0, 9, 0), EXIT];
        assert!(check_reachable("t", &stream, &[("t".to_owned(), 0)]).is_err());
        // Unknown jump opcode.
        let stream = vec![insn(0xa5, 0, 0, 0), EXIT];
        assert!(check_reachable("t", &stream, &[("t".to_owned(), 0)]).is_err());
        // Falls off the end.
        let stream = vec![insn(0xb7, 0, 0, 0)];
        assert!(check_reachable("t", &stream, &[("t".to_owned(), 0)]).is_err());
        // Empty stream.
        assert!(check_reachable("t", &[], &[]).is_err());
    }
}
