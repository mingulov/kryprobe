// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw BTF parser (1A-L12): strict sequential walker over a vmlinux
//! BTF image, extracted from `btf_resolve.rs`.
//!
//! Reusable ELF-adjacent component: parses the header, type records,
//! and string table with no kcrypto knowledge. Resolution (func ids,
//! member offsets) and sensor loading stay in [`crate::btf_resolve`],
//! the sole consumer. Every truncation, unknown kind, or misaligned
//! member offset is [`BtfError`](crate::btf_resolve::BtfError), never
//! a guess. Micro-borrow: none — direct decode against the BTF spec
//! (`Documentation/bpf/btf.rst`, UAPI `linux/btf.h`).

use crate::btf_resolve::BtfError;

/// Raw BTF header length minimum (magic + version/flags + 5 u32s).
const BTF_HDR_MIN: usize = 24;
/// BTF magic (`0xEB9F`), little-endian.
pub(crate) const BTF_MAGIC: u16 = 0xEB9F;
/// BTF version the kernel writes.
pub(crate) const BTF_VERSION: u8 = 1;

/// BTF kinds (`linux/btf.h`): only the aux shapes matter here.
pub(crate) const KIND_INT: u8 = 1;
const KIND_PTR: u8 = 2;
const KIND_ARRAY: u8 = 3;
pub(crate) const KIND_STRUCT: u8 = 4;
const KIND_UNION: u8 = 5;
const KIND_ENUM: u8 = 6;
const KIND_FWD: u8 = 7;
const KIND_TYPEDEF: u8 = 8;
const KIND_VOLATILE: u8 = 9;
const KIND_CONST: u8 = 10;
const KIND_RESTRICT: u8 = 11;
pub(crate) const KIND_FUNC: u8 = 12;
pub(crate) const KIND_FUNC_PROTO: u8 = 13;
const KIND_VAR: u8 = 14;
const KIND_DATASEC: u8 = 15;
const KIND_FLOAT: u8 = 16;
const KIND_DECL_TAG: u8 = 17;
const KIND_TYPE_TAG: u8 = 18;
const KIND_ENUM64: u8 = 19;

/// Anonymous-descent + typedef-chain depth cap (vmlinux nesting is ≤3;
/// the cap only bounds hostile images).
const DESCENT_CAP: usize = 8;

fn bad(reason: String) -> BtfError {
    BtfError::BadBtf { reason }
}

/// One decoded type header: ids are 1-based, `types[id - 1]`.
struct TypeRec {
    kind: u8,
    vlen: u32,
    kind_flag: bool,
    name_off: u32,
    size_or_type: u32,
    /// File offset of the aux records (past the 12-byte header).
    aux_at: usize,
}

/// Parsed BTF image: borrowed bytes + decoded type headers + strtab.
pub(crate) struct Btf<'a> {
    bytes: &'a [u8],
    types: Vec<TypeRec>,
    str_at: usize,
    str_len: usize,
}

fn read_u32(bytes: &[u8], at: usize, what: &str) -> Result<u32, BtfError> {
    bytes
        .get(at..at.saturating_add(4))
        .filter(|w| w.len() == 4)
        .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
        .ok_or_else(|| bad(format!("{what} at {at:#x} runs past the end")))
}

impl<'a> Btf<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, BtfError> {
        if bytes.len() < BTF_HDR_MIN {
            return Err(bad(format!("header truncated ({} bytes)", bytes.len())));
        }
        let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
        if magic != BTF_MAGIC {
            return Err(bad(format!("magic {magic:#x} is not BTF")));
        }
        if bytes[2] != BTF_VERSION {
            return Err(bad(format!("version {} is not BTF v1", bytes[2])));
        }
        let hdr_len = read_u32(bytes, 4, "hdr_len")? as usize;
        if hdr_len < BTF_HDR_MIN {
            return Err(bad(format!("hdr_len {hdr_len} is below 24")));
        }
        let word = |at: usize, what: &str| read_u32(bytes, at, what).map(|w| w as usize);
        let (type_off, type_len) = (word(8, "type_off")?, word(12, "type_len")?);
        let (str_off, str_len) = (word(16, "str_off")?, word(20, "str_len")?);
        let base = |off: usize, len: usize, what: &str| -> Result<(usize, usize), BtfError> {
            let start = hdr_len
                .checked_add(off)
                .ok_or_else(|| bad(format!("{what} offset overflows")))?;
            let end = start
                .checked_add(len)
                .ok_or_else(|| bad(format!("{what} range overflows")))?;
            if end > bytes.len() {
                return Err(bad(format!("{what} range runs past the end")));
            }
            Ok((start, len))
        };
        let (type_at, type_len) = base(type_off, type_len, "type section")?;
        let (str_at, str_len) = base(str_off, str_len, "string section")?;
        // vmlinux strtab starts with the empty string; an empty table
        // cannot name anything, so refuse it outright.
        if str_len == 0 {
            return Err(bad("string section is empty".to_owned()));
        }
        let mut types = Vec::new();
        let mut pos = type_at;
        let type_end = type_at + type_len;
        while pos < type_end {
            if pos + 12 > type_end {
                return Err(bad(format!("type record at {pos:#x} is truncated")));
            }
            let name_off = read_u32(bytes, pos, "type name_off")?;
            let info = read_u32(bytes, pos + 4, "type info")?;
            let size_or_type = read_u32(bytes, pos + 8, "type size/type")?;
            let (kind, vlen, kind_flag) =
                (((info >> 24) & 0x1f) as u8, info & 0xffff, info >> 31 == 1);
            let aux_len = aux_len(kind, vlen)?;
            let aux_at = pos + 12;
            if aux_at + aux_len > type_end {
                return Err(bad(format!(
                    "type record at {pos:#x} aux runs past the end"
                )));
            }
            types.push(TypeRec {
                kind,
                vlen,
                kind_flag,
                name_off,
                size_or_type,
                aux_at,
            });
            pos = aux_at + aux_len;
        }
        Ok(Self {
            bytes,
            types,
            str_at,
            str_len,
        })
    }

    /// String-table bytes at `off` (NUL-terminated, bounds-checked).
    fn str_at(&self, off: u32) -> Result<&[u8], BtfError> {
        let start = (off as usize)
            .checked_add(self.str_at)
            .ok_or_else(|| bad(format!("string offset {off} overflows")))?;
        let end = self.str_at + self.str_len;
        if start >= end {
            return Err(bad(format!("string offset {off} is outside the table")));
        }
        let tail = &self.bytes[start..end];
        let len = tail
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| bad(format!("string at {off} is unterminated")))?;
        Ok(&tail[..len])
    }

    fn name_is(&self, rec: &TypeRec, want: &str) -> Result<bool, BtfError> {
        // Corrupt string refs fail closed (a skipped name could hide
        // the record we want and misreport it as missing).
        Ok(self.str_at(rec.name_off)? == want.as_bytes())
    }

    /// First `FUNC` id with `name` (id order; our 9 are single-definition).
    pub(crate) fn func_id(&self, name: &str) -> Result<Option<u32>, BtfError> {
        for (i, rec) in self.types.iter().enumerate() {
            if rec.kind == KIND_FUNC && self.name_is(rec, name)? {
                return Ok(Some(i as u32 + 1));
            }
        }
        Ok(None)
    }

    /// Chase qualifier wrappers (typedef/const/volatile/restrict) to
    /// the first unwrapped type id (cap-bounded, cycle-guarded).
    /// Dangling ids, void, cycles, and over-long chains are [`bad`]
    /// (corrupt image), never a silent stop.
    fn chase_wrappers(&self, mut id: u32) -> Result<u32, BtfError> {
        let mut seen = [0u32; DESCENT_CAP + 1];
        for depth in 0..=DESCENT_CAP {
            if id == 0 {
                return Err(bad("wrapper chase reached VOID".to_owned()));
            }
            if seen[..depth].contains(&id) {
                return Err(bad("wrapper chase cycles".to_owned()));
            }
            seen[depth] = id;
            let rec = self.rec(id)?;
            match rec.kind {
                KIND_TYPEDEF | KIND_CONST | KIND_VOLATILE | KIND_RESTRICT => {
                    id = rec.size_or_type;
                }
                _ => return Ok(id),
            }
        }
        Err(bad("wrapper chase exceeds the descent cap".to_owned()))
    }

    /// Validate that `name`'s prototype is EXACTLY the qualified
    /// sensor read — `int (struct skcipher_request *)` — and return
    /// its `FUNC` id (round-1 sol-M2/astra-M2, hardened round-2
    /// sol-M4/astra-M7): exactly one argument, arg0 a pointer (after
    /// qualifier chase) to STRUCT `skcipher_request`, return a
    /// signed 32-bit INT at offset 0. Any signature drift refuses
    /// startup rather than mis-keying the join or misreading the
    /// status. Corrupt images stay [`BtfError::BadBtf`]; well-formed
    /// but incompatible prototypes are [`BtfError::BadPrototype`].
    pub(crate) fn lifecycle_proto_id(&self, name: &str) -> Result<u32, BtfError> {
        let bad_proto = |reason: String| BtfError::BadPrototype {
            name: name.to_owned(),
            reason,
        };
        let id = self.func_id(name)?.ok_or_else(|| BtfError::MissingFunc {
            name: name.to_owned(),
        })?;
        let target = self.rec(id)?.size_or_type;
        let proto = self.rec(target)?;
        if proto.kind != KIND_FUNC_PROTO {
            return Err(bad_proto(format!(
                "FUNC target id {target} is kind {}, not FUNC_PROTO",
                proto.kind
            )));
        }
        if proto.vlen != 1 {
            return Err(bad_proto(format!(
                "prototype takes {} arguments, want exactly 1",
                proto.vlen
            )));
        }
        let arg0 = read_u32(self.bytes, proto.aux_at + 4, "proto arg0 type")?;
        let ptr = self.rec(self.chase_wrappers(arg0)?)?;
        if ptr.kind != KIND_PTR {
            return Err(bad_proto("arg0 is not a pointer".to_owned()));
        }
        // The pointee IS the qualified request identity: arg0 must
        // point at STRUCT `skcipher_request` (a pointer to any other
        // type keys the join on a stranger's address).
        let pointee = self.rec(self.chase_wrappers(ptr.size_or_type)?)?;
        if pointee.kind != KIND_STRUCT {
            return Err(bad_proto(format!(
                "arg0 points at kind {}, not STRUCT skcipher_request",
                pointee.kind
            )));
        }
        if !self.name_is(pointee, "skcipher_request")? {
            return Err(bad_proto(
                "arg0 points at the wrong STRUCT, not skcipher_request".to_owned(),
            ));
        }
        let ret = proto.size_or_type;
        if ret == 0 {
            return Err(bad_proto("return is VOID, not a 32-bit int".to_owned()));
        }
        let rec = self.rec(self.chase_wrappers(ret)?)?;
        if rec.kind != KIND_INT {
            return Err(bad_proto("return is not an INT".to_owned()));
        }
        if rec.size_or_type != 4 {
            return Err(bad_proto(format!(
                "return INT is {} bytes, not 4",
                rec.size_or_type
            )));
        }
        // BTF INT data word (`linux/btf.h`): bits [0:8), offset
        // [16:24), encoding [24:28) with bit 0 = SIGNED. All three
        // are exact: a bitfield, an unsigned, or a narrow int would
        // misread errnos.
        let data = read_u32(self.bytes, rec.aux_at, "int data")?;
        let (bits, offset, encoding) = (data & 0xff, (data >> 16) & 0xff, (data >> 24) & 0x0f);
        if bits != 32 {
            return Err(bad_proto(format!("return INT is {bits} bits, not 32")));
        }
        if offset != 0 {
            return Err(bad_proto(format!(
                "return INT has bit offset {offset}, not 0"
            )));
        }
        if encoding & 0x01 == 0 {
            return Err(bad_proto("return INT is not SIGNED".to_owned()));
        }
        Ok(id)
    }

    /// Byte offset of `member` in struct/union `type_name`, descending
    /// into anonymous members (offsets add). TYPEDEF names resolve to
    /// their struct; anything else is missing, never guessed.
    pub(crate) fn member_offset(&self, type_name: &str, member: &str) -> Result<u32, BtfError> {
        let root = self.find_struct(type_name)?;
        let mut path = [0u32; DESCENT_CAP + 1];
        self.member_at(root, member, 0, &mut path)?
            .ok_or_else(|| BtfError::MissingMember {
                type_name: type_name.to_owned(),
                member: member.to_owned(),
            })
    }

    /// Struct/union id for `name`, directly or through one TYPEDEF.
    /// TYPEDEF chains resolve iteratively (cap-bounded, cycle-guarded).
    fn find_struct(&self, name: &str) -> Result<u32, BtfError> {
        for (i, rec) in self.types.iter().enumerate() {
            if matches!(rec.kind, KIND_STRUCT | KIND_UNION) && self.name_is(rec, name)? {
                return Ok(i as u32 + 1);
            }
        }
        let mut next = None;
        for rec in &self.types {
            if rec.kind == KIND_TYPEDEF && self.name_is(rec, name)? {
                next = Some(rec.size_or_type);
                break;
            }
        }
        let mut seen = [0u32; DESCENT_CAP + 1];
        for depth in 0..=DESCENT_CAP {
            let Some(id) = next else { break };
            if id == 0 || seen[..depth].contains(&id) {
                break;
            }
            seen[depth] = id;
            let rec = self.rec(id)?;
            match rec.kind {
                KIND_STRUCT | KIND_UNION => return Ok(id),
                KIND_TYPEDEF | KIND_CONST | KIND_VOLATILE | KIND_RESTRICT => {
                    next = Some(rec.size_or_type);
                }
                _ => break,
            }
        }
        Err(BtfError::MissingType {
            name: name.to_owned(),
        })
    }

    fn rec(&self, id: u32) -> Result<&TypeRec, BtfError> {
        usize::try_from(id)
            .ok()
            .and_then(|id| id.checked_sub(1))
            .and_then(|i| self.types.get(i))
            .ok_or_else(|| bad(format!("dangling type id {id}")))
    }

    /// Chase typedef/const wrappers to the first struct/union
    /// target (1A-M9: extracted so `member_at` reads at one level).
    /// `Ok(None)` when the chain ends anywhere else (cycle, id 0,
    /// non-aggregate); corrupt type ids still fail closed.
    fn anon_target(&self, mtype: u32) -> Result<Option<u32>, BtfError> {
        let mut inner = Some(mtype);
        let mut seen = [0u32; DESCENT_CAP + 1];
        for d in 0..=DESCENT_CAP {
            let Some(tid) = inner else { return Ok(None) };
            if tid == 0 || seen[..d].contains(&tid) {
                return Ok(None);
            }
            seen[d] = tid;
            let trec = self.rec(tid)?;
            match trec.kind {
                KIND_STRUCT | KIND_UNION => return Ok(Some(tid)),
                KIND_TYPEDEF | KIND_CONST | KIND_VOLATILE | KIND_RESTRICT => {
                    inner = Some(trec.size_or_type);
                }
                _ => return Ok(None),
            }
        }
        Ok(None)
    }

    /// Member search under struct/union `id`: `Ok(None)` when absent
    /// here (callers keep looking outward). Alignment/bitfield checks
    /// apply ONLY to the sought member and to anonymous members on the
    /// descent path (fail-closed: our reads are all byte-aligned, and a
    /// bitfield has no byte offset to read): non-sought members —
    /// including bitfields elsewhere in the struct (K5: `task_struct`
    /// carries bitfields before `real_parent`/`tgid`/`comm`) — are
    /// skipped, never fatal.
    fn member_at(
        &self,
        id: u32,
        member: &str,
        depth: usize,
        path: &mut [u32; DESCENT_CAP + 1],
    ) -> Result<Option<u32>, BtfError> {
        if depth > DESCENT_CAP || path[..depth].contains(&id) {
            return Ok(None);
        }
        path[depth] = id;
        let rec = self.rec(id)?;
        if !matches!(rec.kind, KIND_STRUCT | KIND_UNION) {
            return Ok(None);
        }
        for m in 0..rec.vlen as usize {
            let at = rec.aux_at + m * 12;
            let name_off = read_u32(self.bytes, at, "member name_off")?;
            let mtype = read_u32(self.bytes, at + 4, "member type")?;
            let raw = read_u32(self.bytes, at + 8, "member offset")?;
            // Corrupt string refs still fail closed (a skipped name
            // could hide the record we want and misreport it as
            // missing) — but a name that simply is not ours skips.
            let wanted = name_off != 0 && self.str_at(name_off)? == member.as_bytes();
            let descend = name_off == 0 && mtype != 0;
            if !wanted && !descend {
                continue;
            }
            // Bit offset: low 24 bits when the kind flag marks
            // bitfield packing, the whole word otherwise (BTF spec).
            // A nonzero high byte under the kind flag marks a BITFIELD
            // (width in bits): it has no byte offset, so a sought (or
            // descended) bitfield fails closed like a misalignment.
            let bits = if rec.kind_flag {
                raw & 0x00ff_ffff
            } else {
                raw
            };
            let bitfield = rec.kind_flag && raw >> 24 != 0;
            if bitfield || !bits.is_multiple_of(8) {
                return Err(bad(format!(
                    "member at {at:#x} is not byte-aligned ({bits} bits)"
                )));
            }
            let base = bits / 8;
            if wanted {
                return Ok(Some(base));
            }
            if descend {
                // Anonymous member: descend into struct/union shapes
                // (through const/typedef wrappers), offsets add.
                if let Some(tid) = self.anon_target(mtype)?
                    && let Some(off) = self.member_at(tid, member, depth + 1, path)?
                {
                    return Ok(Some(base.checked_add(off).ok_or_else(|| {
                        bad("anonymous member offset overflows".to_owned())
                    })?));
                }
            }
        }
        Ok(None)
    }
}

/// Aux byte length for one type record: fixed shapes assert `vlen == 0`
/// (anything else is malformed BTF); `FUNC`/`VAR` carry linkage
/// (0 static, 1 global) in `vlen`, not a count.
fn aux_len(kind: u8, vlen: u32) -> Result<usize, BtfError> {
    let fixed = |want: usize| {
        if vlen == 0 {
            Ok(want)
        } else {
            Err(bad(format!("kind {kind} carries unexpected vlen {vlen}")))
        }
    };
    let linkage = |want: usize| {
        if vlen <= 1 {
            Ok(want)
        } else {
            Err(bad(format!("kind {kind} carries bogus linkage {vlen}")))
        }
    };
    match kind {
        KIND_INT => fixed(4),
        KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT
        | KIND_FLOAT | KIND_TYPE_TAG => fixed(0),
        KIND_FUNC => linkage(0),
        KIND_VAR => linkage(4),
        KIND_ARRAY => fixed(12),
        // `vlen` is 16 bits: `vlen * 12` (max 786,420) cannot
        // overflow `usize` on any supported target.
        KIND_STRUCT | KIND_UNION | KIND_DATASEC | KIND_ENUM64 => Ok(vlen as usize * 12),
        KIND_ENUM | KIND_FUNC_PROTO => Ok(vlen as usize * 8),
        KIND_DECL_TAG => fixed(4),
        other => Err(bad(format!("unknown BTF kind {other}"))),
    }
}
