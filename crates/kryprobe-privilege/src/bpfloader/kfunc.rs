// SPDX-License-Identifier: GPL-3.0-or-later
//! Session-kfunc stub rewrite (T06 W8): the fsession BPF calls two
//! kfuncs through sentinel immediates — plain `call imm` insns with
//! NO relocations (R4-safe by construction; aya-ebpf 0.2.1 has no
//! kfunc support). Before load, this module rewrites each sentinel
//! to `BPF_PSEUDO_KFUNC_CALL` with the vmlinux BTF FUNC id. An
//! unrewritten sentinel is refused by the verifier as a helper id
//! out of range (fail-closed); a missing kfunc FUNC refuses here
//! with the cause named (fail-closed pre-check — the 7.0+ floor
//! itself is enforced by FSESSION attach acceptance at load).

use super::parse::BpfInsn;
use crate::bpfloader::LoaderError;
use std::collections::HashMap;

/// `call` opcode (`JMP | CALL`).
const OP_CALL: u8 = 0x85;
/// `src_reg` nibble marking a kfunc call (`BPF_PSEUDO_KFUNC_CALL` =
/// 2, UAPI `linux/bpf.h` — 1 is `BPF_PSEUDO_CALL`, a pc-relative
/// subprogram call; writing 1 here makes the verifier read the BTF
/// id as a jump offset and refuse "call to invalid destination",
/// as the 7.0.14 guest proved).
const PSEUDO_KFUNC_CALL: u8 = 2;

/// `bpf_session_is_return` stub sentinel (BPF twin:
/// `KFUNC_IS_RETURN_SENTINEL` in `kcrypto_lifecycle.rs`; bit 31
/// clear, so it fits `i32` alongside real helper ids).
pub(crate) const KFUNC_IS_RETURN_SENTINEL: i32 = 0x5F4B_0001;
/// `bpf_session_cookie` stub sentinel (BPF twin:
/// `KFUNC_COOKIE_SENTINEL`).
pub(crate) const KFUNC_COOKIE_SENTINEL: i32 = 0x5F4B_0002;

/// Rewrite every kfunc stub in `insns`: `call <sentinel>` (exact
/// shape: opcode `CALL`, zero regs, zero offset) becomes the kfunc
/// call with `src_reg = PSEUDO_KFUNC_CALL`, `off = 0` (vmlinux BTF),
/// `imm` = the FUNC id from `ids`.
///
/// Refuses typed when a kfunc id is missing, a BTF id exceeds `i32`
/// range, or the program carries no stubs at all (an `fsession/`
/// section without session calls is not a session program — stale
/// or hand-made object). Sentinel immediates on NON-call insns
/// (data, `ld_imm64` halves) are never touched: only exact-shape
/// calls rewrite.
pub(crate) fn rewrite_kfunc_stubs(
    insns: &mut [BpfInsn],
    section: &str,
    ids: &HashMap<String, u32>,
) -> Result<(), LoaderError> {
    let mut rewritten = 0usize;
    for insn in insns.iter_mut() {
        if insn.code != OP_CALL || insn.dst_src != 0 || insn.off != 0 {
            continue;
        }
        let name = if insn.imm == KFUNC_IS_RETURN_SENTINEL {
            "bpf_session_is_return"
        } else if insn.imm == KFUNC_COOKIE_SENTINEL {
            "bpf_session_cookie"
        } else {
            continue;
        };
        let id = ids.get(name).ok_or_else(|| LoaderError::BadObject {
            reason: format!("kfunc ids lack '{name}' (section '{section}')"),
        })?;
        let imm = i32::try_from(*id).map_err(|_| LoaderError::BadObject {
            reason: format!("kfunc '{name}' BTF id {id} exceeds i32 range"),
        })?;
        insn.dst_src = PSEUDO_KFUNC_CALL << 4;
        insn.imm = imm;
        rewritten += 1;
    }
    if rewritten == 0 {
        return Err(LoaderError::BadObject {
            reason: format!("section '{section}' has no kfunc stubs — not an fsession program"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stub(imm: i32) -> BpfInsn {
        BpfInsn {
            code: OP_CALL,
            dst_src: 0,
            off: 0,
            imm,
        }
    }

    fn ids() -> HashMap<String, u32> {
        HashMap::from([
            ("bpf_session_is_return".to_owned(), 101u32),
            ("bpf_session_cookie".to_owned(), 102u32),
        ])
    }

    #[test]
    fn rewrites_both_stubs_with_btf_ids() {
        let mut insns = vec![
            stub(KFUNC_IS_RETURN_SENTINEL),
            stub(1), // real helper call: untouched
            stub(KFUNC_COOKIE_SENTINEL),
        ];
        rewrite_kfunc_stubs(&mut insns, "fsession/f", &ids()).expect("rewrite");
        assert_eq!(insns[0].dst_src, 0x20); // src_reg = BPF_PSEUDO_KFUNC_CALL
        assert_eq!(insns[0].imm, 101);
        assert_eq!(insns[0].off, 0);
        assert_eq!(insns[1].dst_src, 0);
        assert_eq!(insns[1].imm, 1);
        assert_eq!(insns[2].dst_src, 0x20); // src_reg = BPF_PSEUDO_KFUNC_CALL
        assert_eq!(insns[2].imm, 102);
    }

    #[test]
    fn refuses_stub_free_program() {
        let mut insns = vec![stub(1)];
        let err = rewrite_kfunc_stubs(&mut insns, "fsession/f", &ids()).expect_err("must refuse");
        assert!(matches!(err, LoaderError::BadObject { .. }), "{err:?}");
    }

    #[test]
    fn ignores_sentinel_valued_data() {
        // `ld_imm64` (0x18) carrying a sentinel immediate is data, not
        // a call: never rewritten.
        let mut insns = vec![
            BpfInsn {
                code: 0x18,
                dst_src: 0,
                off: 0,
                imm: KFUNC_IS_RETURN_SENTINEL,
            },
            stub(KFUNC_COOKIE_SENTINEL),
        ];
        rewrite_kfunc_stubs(&mut insns, "fsession/f", &ids()).expect("rewrite");
        assert_eq!(insns[0].dst_src, 0);
        assert_eq!(insns[0].imm, KFUNC_IS_RETURN_SENTINEL);
        assert_eq!(insns[1].dst_src, 0x20); // src_reg = BPF_PSEUDO_KFUNC_CALL
    }

    #[test]
    fn refuses_missing_kfunc_id() {
        let mut insns = vec![stub(KFUNC_IS_RETURN_SENTINEL)];
        let ids = HashMap::from([("bpf_session_cookie".to_owned(), 102u32)]);
        let err = rewrite_kfunc_stubs(&mut insns, "fsession/f", &ids).expect_err("must refuse");
        assert!(matches!(err, LoaderError::BadObject { .. }), "{err:?}");
    }

    #[test]
    fn refuses_id_out_of_range() {
        let mut insns = vec![stub(KFUNC_COOKIE_SENTINEL)];
        let ids = HashMap::from([
            ("bpf_session_is_return".to_owned(), 101u32),
            ("bpf_session_cookie".to_owned(), u32::MAX),
        ]);
        let err = rewrite_kfunc_stubs(&mut insns, "fsession/f", &ids).expect_err("must refuse");
        assert!(matches!(err, LoaderError::BadObject { .. }), "{err:?}");
    }
}
