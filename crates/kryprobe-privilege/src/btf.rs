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
pub(crate) const KIND_PTR: u8 = 2;
pub(crate) const KIND_ARRAY: u8 = 3;
pub(crate) const KIND_STRUCT: u8 = 4;
pub(crate) const KIND_UNION: u8 = 5;
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

    /// Type-record count (P4: the split view's `start_id` is the
    /// base count + 1 — module BTF ids relocate above the base).
    pub(crate) fn type_count(&self) -> u32 {
        self.types.len() as u32
    }

    /// String-table length (P4: the split view's string bias —
    /// module name offsets live in base++module concatenated space).
    pub(crate) fn str_len(&self) -> usize {
        self.str_len
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
    /// sensor read — `int (struct <expected> *)` — and return its
    /// `FUNC` id plus the chased STRUCT pointee id (round-1
    /// sol-M2/astra-M2, hardened round-2 sol-M4/astra-M7, T07-R4-N2
    /// root binding): exactly one argument, arg0 a pointer (after
    /// qualifier chase) to STRUCT `expected` (`skcipher_request` on
    /// the skcipher op sites, `aead_request` on the P5 AEAD op
    /// sites), return a signed 32-bit INT at offset 0. Any signature
    /// drift refuses startup rather than mis-keying the join or
    /// misreading the status. Corrupt images stay
    /// [`BtfError::BadBtf`]; well-formed but incompatible prototypes
    /// are [`BtfError::BadPrototype`].
    pub(crate) fn lifecycle_proto_id(
        &self,
        name: &str,
        expected: &str,
    ) -> Result<(u32, u32), BtfError> {
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
        // point at STRUCT `expected` (a pointer to any other
        // type keys the join on a stranger's address).
        let pointee_id = self.chase_wrappers(ptr.size_or_type)?;
        let pointee = self.rec(pointee_id)?;
        if pointee.kind != KIND_STRUCT {
            return Err(bad_proto(format!(
                "arg0 points at kind {}, not STRUCT {expected}",
                pointee.kind
            )));
        }
        if !self.name_is(pointee, expected)? {
            return Err(bad_proto(format!(
                "arg0 points at the wrong STRUCT, not {expected}"
            )));
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
        // [16:24), encoding [24:28) with bit 0 = SIGNED, bit 1 =
        // CHAR, bit 2 = BOOL. The encoding is EXACT, not a
        // SIGNED-bit test: SIGNED combined with CHAR or BOOL bits
        // is a different type, and the return gate is exact.
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
        if encoding != 0x01 {
            return Err(bad_proto(format!(
                "return INT encoding is {encoding:#x}, not exactly SIGNED"
            )));
        }
        Ok((id, pointee_id))
    }

    /// Validate that `name`'s prototype is EXACTLY the qualified
    /// allocation-sensor read — `struct <expected> *(const char *,
    /// u32, u32)` — and return its `FUNC` id plus the chased STRUCT
    /// pointee id (T07.2, same refuse-on-drift discipline as
    /// [`Btf::lifecycle_proto_id`]): exactly three arguments, arg0 a
    /// pointer (after qualifier chase) to 1-byte INT (`char` — the
    /// bounded name copy reads raw bytes, so the width pins but the
    /// signedness does not), arg1/arg2 4-byte INTs (the type/mask
    /// words travel as unshifted `u32` copies — the width pins, the
    /// encoding does not), return a pointer to STRUCT `expected`
    /// (`crypto_skcipher` on the skcipher alloc site, `crypto_aead`
    /// on the P5 AEAD alloc site — the success chase reads
    /// `__crt_alg` at the resolved offset, so a pointer to any other
    /// type would mis-chase). Corrupt images stay
    /// [`BtfError::BadBtf`]; well-formed but incompatible prototypes
    /// are [`BtfError::BadPrototype`].
    pub(crate) fn alloc_proto_id(
        &self,
        name: &str,
        expected: &str,
    ) -> Result<(u32, u32), BtfError> {
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
        if proto.vlen != 3 {
            return Err(bad_proto(format!(
                "prototype takes {} arguments, want exactly 3",
                proto.vlen
            )));
        }
        let arg0 = read_u32(self.bytes, proto.aux_at + 4, "proto arg0 type")?;
        let ptr = self.rec(self.chase_wrappers(arg0)?)?;
        if ptr.kind != KIND_PTR {
            return Err(bad_proto("arg0 is not a pointer".to_owned()));
        }
        // The name copy reads raw bytes through this pointer: the
        // pointee must be 1-byte INT (`char` — any wider pointee
        // changes what a byte copy means).
        let pointee = self.rec(self.chase_wrappers(ptr.size_or_type)?)?;
        if pointee.kind != KIND_INT {
            return Err(bad_proto(format!(
                "arg0 points at kind {}, not INT char",
                pointee.kind
            )));
        }
        if pointee.size_or_type != 1 {
            return Err(bad_proto(format!(
                "arg0 pointee INT is {} bytes, not 1",
                pointee.size_or_type
            )));
        }
        // Type/mask words: 4-byte INTs (the BPF copies the low 32
        // bits uninterpreted — a wider scalar would truncate, a
        // non-scalar would misread).
        for (n, at) in [(1u32, proto.aux_at + 12), (2u32, proto.aux_at + 20)] {
            let arg = read_u32(self.bytes, at, "proto arg type")?;
            let rec = self.rec(self.chase_wrappers(arg)?)?;
            if rec.kind != KIND_INT {
                return Err(bad_proto(format!("arg{n} is not an INT")));
            }
            if rec.size_or_type != 4 {
                return Err(bad_proto(format!(
                    "arg{n} INT is {} bytes, not 4",
                    rec.size_or_type
                )));
            }
        }
        // The success value is a frontend pointer the exit run
        // chases: it must point at STRUCT `expected`.
        let ret = proto.size_or_type;
        if ret == 0 {
            return Err(bad_proto("return is VOID, not a tfm pointer".to_owned()));
        }
        let rec = self.rec(self.chase_wrappers(ret)?)?;
        if rec.kind != KIND_PTR {
            return Err(bad_proto("return is not a pointer".to_owned()));
        }
        let pointee_id = self.chase_wrappers(rec.size_or_type)?;
        let pointee = self.rec(pointee_id)?;
        if pointee.kind != KIND_STRUCT {
            return Err(bad_proto(format!(
                "return points at kind {}, not STRUCT {expected}",
                pointee.kind
            )));
        }
        if !self.name_is(pointee, expected)? {
            return Err(bad_proto(format!(
                "return points at the wrong STRUCT, not {expected}"
            )));
        }
        Ok((id, pointee_id))
    }

    /// FUNC id of `name` proven to be the destroy shape
    /// `void (void *, struct crypto_tfm *)`, plus the chased STRUCT
    /// pointee id (T07.3): exactly two
    /// args, arg0 a pointer (the frontend `mem` — pointee
    /// unchecked: any pointer-typed arg0 carries the frontend
    /// address, and the tracker classifies null/ERR as a no-op
    /// release), arg1 a pointer at STRUCT `crypto_tfm` (the
    /// refcount read lands in it — a wrong pointee would read a
    /// stranger's word as a refcount), and a VOID return (the
    /// exit run emits no status — reading a return register from
    /// a void call would emit garbage as truth).
    pub(crate) fn destroy_proto_id(&self, name: &str) -> Result<(u32, u32), BtfError> {
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
        if proto.vlen != 2 {
            return Err(bad_proto(format!(
                "prototype takes {} arguments, want exactly 2",
                proto.vlen
            )));
        }
        let arg0 = read_u32(self.bytes, proto.aux_at + 4, "proto arg0 type")?;
        let mem = self.rec(self.chase_wrappers(arg0)?)?;
        if mem.kind != KIND_PTR {
            return Err(bad_proto("arg0 is not a pointer".to_owned()));
        }
        let arg1 = read_u32(self.bytes, proto.aux_at + 12, "proto arg1 type")?;
        let tfm = self.rec(self.chase_wrappers(arg1)?)?;
        if tfm.kind != KIND_PTR {
            return Err(bad_proto("arg1 is not a pointer".to_owned()));
        }
        let pointee_id = self.chase_wrappers(tfm.size_or_type)?;
        let pointee = self.rec(pointee_id)?;
        if pointee.kind != KIND_STRUCT {
            return Err(bad_proto(format!(
                "arg1 points at kind {}, not STRUCT crypto_tfm",
                pointee.kind
            )));
        }
        if !self.name_is(pointee, "crypto_tfm")? {
            return Err(bad_proto(
                "arg1 points at the wrong STRUCT, not crypto_tfm".to_owned(),
            ));
        }
        if proto.size_or_type != 0 {
            return Err(bad_proto("return is not VOID".to_owned()));
        }
        Ok((id, pointee_id))
    }

    /// Prove the FUNC_PROTO return at `ret` is EXACTLY a SIGNED
    /// 32-bit INT (the T07.4 errno gate): nonzero type id, INT
    /// kind, 4 bytes, 32 bits, zero bit offset, and encoding
    /// exactly SIGNED — same refusal discipline as
    /// [`Btf::lifecycle_proto_id`]'s inline gate (a sign, width,
    /// or encoding change would invert errno reads).
    fn int_return_exact(&self, ret: u32, name: &str) -> Result<(), BtfError> {
        let bad_proto = |reason: String| BtfError::BadPrototype {
            name: name.to_owned(),
            reason,
        };
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
        if encoding != 0x01 {
            return Err(bad_proto(format!(
                "return INT encoding is {encoding:#x}, not exactly SIGNED"
            )));
        }
        Ok(())
    }

    /// Prove the INT `id` carries a full 32-bit VALUE at bit
    /// offset 0 (T07-R2-01: the BPF reads exactly one u32 there — a
    /// 4-byte container holding a shifted/narrower value would
    /// misread, so the encoding must prove VALUE width, not just
    /// storage width). Encoding (signed/unsigned/char/bool) stays
    /// unpinned: the read compares/copies the raw u32, whose bits
    /// don't depend on it. (Errno returns keep their own SIGNED
    /// pin in [`Btf::int_return_exact`] — a sign change would
    /// invert error reads.)
    fn int_value_exact(&self, id: u32, what: &str) -> Result<(), BtfError> {
        self.int_value_bits(id, 32, what)
    }

    /// Prove the INT `id` carries a full `want`-bit VALUE at bit
    /// offset 0 (T07-R3-06: the byte-array element proof shares
    /// the counter's VALUE-width rule — an 8-bit want pins the
    /// driver-name char the BPF copies byte-wise).
    fn int_value_bits(&self, id: u32, want: u32, what: &str) -> Result<(), BtfError> {
        let rec = self.rec(self.chase_wrappers(id)?)?;
        if rec.kind != KIND_INT {
            return Err(bad(format!("{what} is kind {}, not INT", rec.kind)));
        }
        // T07-R4-02: exact byte-size comparison — the old
        // `size * 8` multiplication wrapped on malformed sizes
        // (fail-open pass in release, panic in debug/test).
        if rec.size_or_type != want / 8 {
            return Err(bad(format!(
                "{what} INT is {} bytes, not {}",
                rec.size_or_type,
                want / 8
            )));
        }
        let data = read_u32(self.bytes, rec.aux_at, "int data")?;
        let (bits, offset) = (data & 0xff, (data >> 16) & 0xff);
        if bits != want {
            return Err(bad(format!("{what} INT is {bits} bits, not {want}")));
        }
        if offset != 0 {
            return Err(bad(format!("{what} INT has bit offset {offset}, not 0")));
        }
        Ok(())
    }

    /// Prove the FUNC_PROTO argument at `at` is a 4-byte INT (the
    /// T07.4 length gate): scalar length words travel as unshifted
    /// `u32` copies — the width pins, the signedness does not (a
    /// wider scalar would truncate, a non-scalar would misread).
    /// (T07-R2-01: same VALUE-width proof as the counter — a
    /// shifted/narrow encoding in 4-byte storage would misread
    /// the length exactly like the counter.)
    fn int_arg_4(&self, at: usize, arg: &str, name: &str) -> Result<(), BtfError> {
        let bad_proto = |reason: String| BtfError::BadPrototype {
            name: name.to_owned(),
            reason,
        };
        let id = read_u32(self.bytes, at, "proto arg type")?;
        let rec = self.rec(self.chase_wrappers(id)?)?;
        if rec.kind != KIND_INT {
            return Err(bad_proto(format!("{arg} is not an INT")));
        }
        if rec.size_or_type != 4 {
            return Err(bad_proto(format!(
                "{arg} INT is {} bytes, not 4",
                rec.size_or_type
            )));
        }
        let data = read_u32(self.bytes, rec.aux_at, "int data")?;
        let (bits, offset) = (data & 0xff, (data >> 16) & 0xff);
        if bits != 32 {
            return Err(bad_proto(format!("{arg} INT is {bits} bits, not 32")));
        }
        if offset != 0 {
            return Err(bad_proto(format!(
                "{arg} INT has bit offset {offset}, not 0"
            )));
        }
        Ok(())
    }

    /// FUNC id of `name` proven to be the setkey shape
    /// `int (<frontend> *, const u8 *, unsigned int)` (T07.4),
    /// plus the chased STRUCT pointee id:
    /// exactly three arguments, arg0 a pointer (after qualifier
    /// chase) at STRUCT `frontend` (the joined transform identity
    /// — a pointer to any other type keys the epoch on a
    /// stranger's address), arg1 a pointer (the key buffer
    /// ADDRESS pins the register shape; its pointee is NEVER
    /// READ — the validator deliberately blesses no pointee, so
    /// no future reader can mistake validation for a dereference
    /// license), arg2 a 4-byte INT (the key length), and a SIGNED
    /// 32-bit INT return (the errno). Corrupt images stay
    /// [`BtfError::BadBtf`]; well-formed but incompatible
    /// prototypes are [`BtfError::BadPrototype`].
    pub(crate) fn setkey_proto_id(
        &self,
        name: &str,
        frontend: &str,
    ) -> Result<(u32, u32), BtfError> {
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
        if proto.vlen != 3 {
            return Err(bad_proto(format!(
                "prototype takes {} arguments, want exactly 3",
                proto.vlen
            )));
        }
        let arg0 = read_u32(self.bytes, proto.aux_at + 4, "proto arg0 type")?;
        let ptr = self.rec(self.chase_wrappers(arg0)?)?;
        if ptr.kind != KIND_PTR {
            return Err(bad_proto("arg0 is not a pointer".to_owned()));
        }
        let pointee_id = self.chase_wrappers(ptr.size_or_type)?;
        let pointee = self.rec(pointee_id)?;
        if pointee.kind != KIND_STRUCT {
            return Err(bad_proto(format!(
                "arg0 points at kind {}, not STRUCT {frontend}",
                pointee.kind
            )));
        }
        if !self.name_is(pointee, frontend)? {
            return Err(bad_proto(format!(
                "arg0 points at the wrong STRUCT, not {frontend}"
            )));
        }
        let arg1 = read_u32(self.bytes, proto.aux_at + 12, "proto arg1 type")?;
        let key = self.rec(self.chase_wrappers(arg1)?)?;
        if key.kind != KIND_PTR {
            return Err(bad_proto("arg1 is not a pointer".to_owned()));
        }
        self.int_arg_4(proto.aux_at + 20, "arg2", name)?;
        self.int_return_exact(proto.size_or_type, name)?;
        Ok((id, pointee_id))
    }

    /// FUNC id of `name` proven to be the setauthsize shape
    /// `int (struct crypto_aead *, unsigned int)` (T07.4), plus the
    /// chased STRUCT pointee id: exactly
    /// two arguments, arg0 a pointer at STRUCT `crypto_aead` (the
    /// joined transform identity), arg1 a 4-byte INT (the authsize),
    /// and a SIGNED 32-bit INT return (the errno). Same
    /// refuse-on-drift discipline as [`Btf::setkey_proto_id`].
    pub(crate) fn setauthsize_proto_id(&self, name: &str) -> Result<(u32, u32), BtfError> {
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
        if proto.vlen != 2 {
            return Err(bad_proto(format!(
                "prototype takes {} arguments, want exactly 2",
                proto.vlen
            )));
        }
        let arg0 = read_u32(self.bytes, proto.aux_at + 4, "proto arg0 type")?;
        let ptr = self.rec(self.chase_wrappers(arg0)?)?;
        if ptr.kind != KIND_PTR {
            return Err(bad_proto("arg0 is not a pointer".to_owned()));
        }
        let pointee_id = self.chase_wrappers(ptr.size_or_type)?;
        let pointee = self.rec(pointee_id)?;
        if pointee.kind != KIND_STRUCT {
            return Err(bad_proto(format!(
                "arg0 points at kind {}, not STRUCT crypto_aead",
                pointee.kind
            )));
        }
        if !self.name_is(pointee, "crypto_aead")? {
            return Err(bad_proto(
                "arg0 points at the wrong STRUCT, not crypto_aead".to_owned(),
            ));
        }
        self.int_arg_4(proto.aux_at + 12, "arg1", name)?;
        self.int_return_exact(proto.size_or_type, name)?;
        Ok((id, pointee_id))
    }

    /// Byte offset of `member` in struct/union `type_name`, descending
    /// into anonymous members (offsets add). TYPEDEF names resolve to
    /// their struct; anything else is missing, never guessed.
    pub(crate) fn member_offset(&self, type_name: &str, member: &str) -> Result<u32, BtfError> {
        self.member_typed(type_name, member).map(|(off, _)| off)
    }

    /// Byte offset AND leaf type id of `member` in struct/union
    /// `type_name` (D3: offsets alone don't prove the dereference
    /// contract — the shape validators below chase the type id to
    /// prove pointer targets, embedded bases, name-array extents,
    /// and counter widths before any BPF read trusts the offset).
    pub(crate) fn member_typed(
        &self,
        type_name: &str,
        member: &str,
    ) -> Result<(u32, u32), BtfError> {
        let root = self.find_struct(type_name)?;
        self.member_typed_in(root, type_name, member)
    }

    /// Id-rooted member lookup core (T07-R3-09): `root` is an
    /// already-bound STRUCT/UNION id (from [`Btf::find_struct`] or a
    /// verified chase), so repeated consultations of one name cannot
    /// drift across duplicate BTF definitions. `type_name` is the
    /// bound name — carried for error context only, never re-looked-up.
    pub(crate) fn member_typed_in(
        &self,
        root: u32,
        type_name: &str,
        member: &str,
    ) -> Result<(u32, u32), BtfError> {
        let mut path = [0u32; DESCENT_CAP + 1];
        self.member_at(root, member, 0, &mut path)?
            .ok_or_else(|| BtfError::MissingMember {
                type_name: type_name.to_owned(),
                member: member.to_owned(),
            })
    }

    /// Offset AND chased pointee STRUCT id of `member` of the
    /// already-bound STRUCT/UNION `root` (T07-R3-09: the resolver binds
    /// each entry name ONCE via [`Btf::find_struct`] and threads the id
    /// — re-resolving the name per member would mix offsets across
    /// duplicate BTF definitions; `type_name` rides along for error
    /// context only). The member must prove a pointer at STRUCT/UNION
    /// `pointee` (wrappers chased on both sides): the BPF chase may
    /// dereference it and read the pointee at further resolved
    /// offsets. Anything else (non-pointer, wrong pointee, missing)
    /// refuses — a valid offset with a lying type would mis-chase.
    /// The 8-byte pointer read must sit inside the parent (R4
    /// containment — the BPF target is 64-bit, pointers read u64).
    pub(crate) fn member_ptr_target_in(
        &self,
        root: u32,
        type_name: &str,
        member: &str,
        pointee: &str,
    ) -> Result<(u32, u32), BtfError> {
        let (off, mtype) = self.member_typed_in(root, type_name, member)?;
        let ptr = self.rec(self.chase_wrappers(mtype)?)?;
        if ptr.kind != KIND_PTR {
            return Err(bad(format!(
                "{type_name}.{member} is kind {}, not a pointer",
                ptr.kind
            )));
        }
        let target_id = self.chase_wrappers(ptr.size_or_type)?;
        let target = self.rec(target_id)?;
        if !matches!(target.kind, KIND_STRUCT | KIND_UNION) {
            return Err(bad(format!(
                "{type_name}.{member} points at kind {}, not STRUCT {pointee}",
                target.kind
            )));
        }
        if !self.name_is(target, pointee)? {
            return Err(bad(format!(
                "{type_name}.{member} points at the wrong STRUCT, not {pointee}"
            )));
        }
        self.check_contained_in(root, type_name, off, 8)?;
        Ok((off, target_id))
    }

    /// Offset AND chased embedded STRUCT id of `member` of the
    /// already-bound STRUCT/UNION `root` (T07-R3-09: ids thread from a
    /// single [`Btf::find_struct`] bind per entry name — `type_name`
    /// rides along for error context only). The member must prove an
    /// embedded STRUCT/UNION `name` (wrappers chased): the BPF may add
    /// further member offsets to it directly (no dereference). A
    /// pointer, scalar, or wrong-typed aggregate refuses — adding into
    /// a pointer would read the pointer's bytes as a struct. The whole
    /// embedded extent must sit inside the parent (R4 containment —
    /// further offsets add into it) and must be NONEMPTY (T07-R2-02:
    /// adding offsets into a zero-size embedded struct reads past its
    /// proven extent).
    pub(crate) fn member_embedded_target_in(
        &self,
        root: u32,
        type_name: &str,
        member: &str,
        name: &str,
    ) -> Result<(u32, u32), BtfError> {
        let (off, mtype) = self.member_typed_in(root, type_name, member)?;
        let inner_id = self.chase_wrappers(mtype)?;
        let inner = self.rec(inner_id)?;
        if !matches!(inner.kind, KIND_STRUCT | KIND_UNION) {
            return Err(bad(format!(
                "{type_name}.{member} is kind {}, not embedded STRUCT {name}",
                inner.kind
            )));
        }
        if !self.name_is(inner, name)? {
            return Err(bad(format!(
                "{type_name}.{member} embeds the wrong STRUCT, not {name}"
            )));
        }
        if inner.size_or_type == 0 {
            return Err(bad(format!(
                "{type_name}.{member} embeds an empty STRUCT {name} — no extent to add into"
            )));
        }
        self.check_contained_in(root, type_name, off, inner.size_or_type)?;
        Ok((off, inner_id))
    }

    /// Offset of `member` of the already-bound STRUCT/UNION `root`
    /// (T07-R3-09: ids thread from a single [`Btf::find_struct`] bind
    /// per entry name — `type_name` rides along for error context
    /// only), proven to be a byte array of at least `min_len` bytes
    /// (ARRAY of 1-byte INT, `nelems` covering the BPF copy bound):
    /// the bounded string copy may fill `min_len` bytes from it.
    /// Shorter arrays refuse — copying past the member would read the
    /// next field as name bytes. The copied extent must also sit
    /// inside the parent (R4 containment).
    pub(crate) fn member_bytes_in(
        &self,
        root: u32,
        type_name: &str,
        member: &str,
        min_len: u32,
    ) -> Result<u32, BtfError> {
        let (off, mtype) = self.member_typed_in(root, type_name, member)?;
        let arr = self.rec(self.chase_wrappers(mtype)?)?;
        if arr.kind != KIND_ARRAY {
            return Err(bad(format!(
                "{type_name}.{member} is kind {}, not a byte ARRAY",
                arr.kind
            )));
        }
        let (elem, nelems) = self.array_shape(arr)?;
        // T07-R3-06: the element must prove an 8-bit zero-offset
        // VALUE, not just 1-byte storage — a 4-bit value in a
        // 1-byte container would copy a lying char.
        self.int_value_bits(elem, 8, &format!("{type_name}.{member} array element"))?;
        if nelems < min_len {
            return Err(bad(format!(
                "{type_name}.{member} array holds {nelems} bytes, fewer than {min_len}"
            )));
        }
        self.check_contained_in(root, type_name, off, min_len)?;
        Ok(off)
    }

    /// Offset of `member` of the already-bound STRUCT/UNION `root`
    /// (T07-R3-09: ids thread from a single [`Btf::find_struct`] bind
    /// per entry name — `type_name` rides along for error context
    /// only), proven to carry the counter value in its FIRST 4 bytes
    /// (R4: the BPF reads exactly one u32 there and the tracker treats
    /// 1 as final-free proof, so the shape must prove the VALUE, not
    /// just the width). Accepted: an INT of EXACTLY 4 bytes with a full
    /// 32-bit zero-offset encoding (T07-R2-01: storage width alone
    /// proves nothing — a 4-byte container with a shifted/narrow value
    /// misreads), or a 4-byte STRUCT/UNION with a proven 4-byte INT
    /// word at byte 0 (the `refcount_t`/`atomic_t` shape — the whole
    /// wrapper IS the one counter word). Refused: wider INTs (a 64-bit
    /// `0x1_0000_0001` reads a lying low word), narrowed/shifted
    /// encodings, multi-word wrappers (a marker before the counter
    /// reads the marker — size ≠ 4 proves nothing about word 0's
    /// meaning), pointers, and narrower shapes. The 4-byte read
    /// must also sit inside the parent (`off + 4 ≤ parent size` —
    /// containment, same as every lifecycle read).
    pub(crate) fn member_counter_in(
        &self,
        root: u32,
        type_name: &str,
        member: &str,
    ) -> Result<u32, BtfError> {
        let (off, mtype) = self.member_typed_in(root, type_name, member)?;
        let target = self.chase_wrappers(mtype)?;
        let rec = self.rec(target)?;
        let is_counter = match rec.kind {
            KIND_INT => {
                self.int_value_exact(target, &format!("{type_name}.{member}"))?;
                true
            }
            KIND_STRUCT | KIND_UNION => {
                rec.size_or_type == 4 && self.counter_word_at_zero(target, 0)?
            }
            _ => false,
        };
        if !is_counter {
            return Err(bad(format!(
                "{type_name}.{member} is kind {} size {}, not a first-word 4-byte counter",
                rec.kind, rec.size_or_type
            )));
        }
        self.check_contained_in(root, type_name, off, 4)?;
        Ok(off)
    }

    /// True when struct/union `id` carries a 4-byte INT word at byte
    /// 0 (R4 counter-leaf proof: some member sits at byte offset 0
    /// with a proven 4-byte INT leaf — a leading marker or a wider
    /// counter leaves no such word; T07-R2-01: the leaf INT must
    /// prove VALUE width too — a shifted/narrow encoding in
    /// 4-byte storage refuses, never qualifies by size alone).
    /// One nesting level descends (the real `refcount_t {
    /// atomic_t refs; }` → `atomic_t { int counter; }` chain —
    /// each wrapper must itself be exactly 4 bytes, so a marker
    /// beside the nested counter still refuses). T07-R4-N1:
    /// EVERY view overlapping word 0 must prove — a bitfield /
    /// misaligned / shifted view starting inside [0,32) fails the
    /// word (union alias or crowded struct: the word is
    /// ambiguous), so a full-width alias can never launder an
    /// unproven overlapping sibling and member order never
    /// decides. T07-R3-08: EVERY byte-aligned word-0 view must
    /// prove — overlapping union views are unanimous.
    /// T07-R5-01: a zero-type (VOID) view overlapping word 0
    /// proves nothing and fails the word (no silent skip).
    fn counter_word_at_zero(&self, id: u32, depth: usize) -> Result<bool, BtfError> {
        if depth > 2 {
            return Ok(false);
        }
        let rec = self.rec(id)?;
        if !matches!(rec.kind, KIND_STRUCT | KIND_UNION) {
            return Ok(false);
        }
        let mut proved_any = false;
        for m in 0..rec.vlen as usize {
            let at = rec.aux_at + m * 12;
            let mtype = read_u32(self.bytes, at + 4, "counter member type")?;
            let raw = read_u32(self.bytes, at + 8, "counter member offset")?;
            let bits = if rec.kind_flag {
                raw & 0x00ff_ffff
            } else {
                raw
            };
            if mtype == 0 {
                // T07-R5-01: a zero-type (VOID) member overlapping
                // word 0 fails the word — the id carries no proof,
                // so an overlapping VOID view is an unproven
                // overlapping sibling exactly like N1 (skipping it
                // would let a full-width alias launder it and dodge
                // the wrapper-chase VOID refusal). Only VOID views
                // fully past [0,32) stay skipped (genuinely
                // different words).
                if bits < 32 {
                    return Ok(false);
                }
                continue;
            }
            let bitfield = rec.kind_flag && raw >> 24 != 0;
            if bitfield || !bits.is_multiple_of(8) || bits / 8 != 0 {
                // T07-R4-N1: a view starting inside word 0 overlaps
                // it — an overlapping view that cannot prove the word
                // (bitfield, sub-byte, or shifted member offset) makes
                // word 0 ambiguous (union alias or crowded struct), so
                // the word does NOT qualify. Only views fully past
                // [0,32) are genuinely different words and stay skipped.
                if bits < 32 {
                    return Ok(false);
                }
                continue;
            }
            let target = self.chase_wrappers(mtype)?;
            let leaf = self.rec(target)?;
            if leaf.kind == KIND_INT {
                // Fail fast (never skip-and-continue): word 0 names
                // an INT, so the wrapper's counter claim stands or
                // falls on THIS leaf's encoding — a malformed leaf
                // must refuse the wrapper, not fall through to a
                // sibling that happens to sit at 0 (union overlap).
                self.int_value_exact(target, "counter leaf")?;
                proved_any = true;
                continue;
            }
            if matches!(leaf.kind, KIND_STRUCT | KIND_UNION)
                && leaf.size_or_type == 4
                && self.counter_word_at_zero(target, depth + 1)?
            {
                proved_any = true;
                continue;
            }
            // An at-0 view that proves nothing makes word 0
            // ambiguous (union overlap with an unproven sibling,
            // or a non-counter aggregate at 0): the word does NOT
            // qualify, regardless of what other views prove.
            return Ok(false);
        }
        Ok(proved_any)
    }

    /// Byte extent of the member TYPE `id` (T07-R2-02: per-level
    /// containment needs each member's storage — fixed sizes
    /// chase through wrappers; arrays multiply out (depth-capped:
    /// corrupt self-nesting refuses); anything else is malformed
    /// BTF, never guessed. Pointers read u64 (the 64-bit BPF
    /// target — same width the pointer proof checks).
    fn type_extent(&self, id: u32) -> Result<u32, BtfError> {
        self.type_extent_at(id, 0)
    }

    /// Depth-capped worker behind [`Btf::type_extent`].
    fn type_extent_at(&self, id: u32, depth: usize) -> Result<u32, BtfError> {
        if depth > DESCENT_CAP {
            return Err(bad("member type nesting exceeds the descent cap".to_owned()));
        }
        let rec = self.rec(self.chase_wrappers(id)?)?;
        match rec.kind {
            KIND_INT | KIND_STRUCT | KIND_UNION | KIND_ENUM | KIND_ENUM64 | KIND_FLOAT => {
                Ok(rec.size_or_type)
            }
            KIND_PTR => Ok(8),
            KIND_ARRAY => {
                let (elem, nelems) = self.array_shape(rec)?;
                let elem_extent = self.type_extent_at(elem, depth + 1)?;
                nelems
                    .checked_mul(elem_extent)
                    .ok_or_else(|| bad(format!("array {nelems} x {elem_extent} bytes overflows")))
            }
            _ => Err(bad(format!(
                "member type id {id} is kind {}, not sized storage",
                rec.kind
            ))),
        }
    }

    /// Containment (R4): the `width`-byte BPF read at root-relative
    /// `off` must sit inside the parent struct/union (a member
    /// offset past the parent's size — corrupt or drifted BTF —
    /// refuses instead of reading the next object as the member).
    /// The parent extent comes from the bound `root` id (T07-R3-09),
    /// never a re-looked-up name.
    fn check_contained_in(
        &self,
        root: u32,
        type_name: &str,
        off: u32,
        width: u32,
    ) -> Result<(), BtfError> {
        let size = self.rec(root)?.size_or_type;
        let end = off
            .checked_add(width)
            .ok_or_else(|| bad(format!("{type_name} read offset {off} + {width} overflows")))?;
        if end > size {
            return Err(bad(format!(
                "{type_name} read [{off}..{end}) escapes the {size}-byte parent"
            )));
        }
        Ok(())
    }

    /// ARRAY shape: (element type id, element count). Index-type
    /// ignorance is deliberate (any index addresses the same
    /// elements); malformed aux refuses.
    fn array_shape(&self, arr: &TypeRec) -> Result<(u32, u32), BtfError> {
        let elem = read_u32(self.bytes, arr.aux_at, "array elem_type")?;
        let nelems = read_u32(self.bytes, arr.aux_at + 8, "array nelems")?;
        Ok((elem, nelems))
    }

    /// Struct/union id for `name`, directly or through one TYPEDEF.
    /// TYPEDEF chains resolve iteratively (cap-bounded, cycle-guarded).
    pub(crate) fn find_struct(&self, name: &str) -> Result<u32, BtfError> {
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
        // T07-R3-10: a cycle or an over-long chain is INCOMPLETE
        // (`TraversalIncomplete`), never `MissingType` — the name may
        // well denote a struct past the break. Only a genuinely absent
        // name, a VOID end, or a non-aggregate end (the name denotes
        // something that provably is NOT a struct) is `MissingType`.
        let mut seen = [0u32; DESCENT_CAP + 1];
        let mut capped = true;
        for depth in 0..=DESCENT_CAP {
            let Some(id) = next else {
                capped = false;
                break;
            };
            if seen[..depth].contains(&id) {
                return Err(BtfError::TraversalIncomplete {
                    sought: name.to_owned(),
                    detail: format!("typedef chain cycles at type id {id}"),
                });
            }
            if id == 0 {
                capped = false;
                break;
            }
            seen[depth] = id;
            let rec = self.rec(id)?;
            match rec.kind {
                KIND_STRUCT | KIND_UNION => return Ok(id),
                KIND_TYPEDEF | KIND_CONST | KIND_VOLATILE | KIND_RESTRICT => {
                    next = Some(rec.size_or_type);
                }
                _ => {
                    capped = false;
                    break;
                }
            }
        }
        if capped {
            return Err(BtfError::TraversalIncomplete {
                sought: name.to_owned(),
                detail: format!("typedef chain exceeds {DESCENT_CAP} levels"),
            });
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
    /// `Ok(None)` ONLY for a proven dead end (a non-aggregate carrier
    /// has no members to search); a cycle or an over-long chain is an
    /// INCOMPLETE search ([`BtfError::TraversalIncomplete`], T07-R3-10
    /// — never `None`, which would read as proven absence), VOID is
    /// malformed BTF (no valid C anonymous member is void), and
    /// corrupt type ids still fail closed.
    fn anon_target(&self, mtype: u32, member: &str) -> Result<Option<u32>, BtfError> {
        let mut inner = Some(mtype);
        let mut seen = [0u32; DESCENT_CAP + 1];
        for d in 0..=DESCENT_CAP {
            let Some(tid) = inner else { return Ok(None) };
            if seen[..d].contains(&tid) {
                return Err(BtfError::TraversalIncomplete {
                    sought: member.to_owned(),
                    detail: format!("anonymous wrapper chain cycles at type id {tid}"),
                });
            }
            if tid == 0 {
                return Err(bad(format!(
                    "anonymous member for '{member}' chains through VOID"
                )));
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
        Err(BtfError::TraversalIncomplete {
            sought: member.to_owned(),
            detail: format!("anonymous wrapper chain exceeds {DESCENT_CAP} levels"),
        })
    }

    /// Member search under struct/union `id`: `Ok(None)` ONLY for a
    /// proven absence (the full scan found no such member down any
    /// completed path — callers keep looking outward). Returns the byte
    /// offset AND the leaf member's type id (the shape validators chase
    /// the type; plain offset callers ignore it). A cycle or an
    /// over-deep descent is an INCOMPLETE search
    /// ([`BtfError::TraversalIncomplete`], T07-R3-10 — never `None`:
    /// `None` becomes `MissingMember`, and for `refcnt` that would
    /// soft-select always-final mode and retire retained releases).
    /// Alignment/bitfield checks apply ONLY to the sought member and
    /// to anonymous members on the descent path (fail-closed: our
    /// reads are all byte-aligned, and a bitfield has no byte offset
    /// to read): non-sought members — including bitfields elsewhere
    /// in the struct (K5: `task_struct` carries bitfields before
    /// `real_parent`/`tgid`/`comm`) — are skipped, never fatal.
    fn member_at(
        &self,
        id: u32,
        member: &str,
        depth: usize,
        path: &mut [u32; DESCENT_CAP + 1],
    ) -> Result<Option<(u32, u32)>, BtfError> {
        if path[..depth].contains(&id) {
            return Err(BtfError::TraversalIncomplete {
                sought: member.to_owned(),
                detail: format!("anonymous member search cycles at type id {id}"),
            });
        }
        if depth > DESCENT_CAP {
            return Err(BtfError::TraversalIncomplete {
                sought: member.to_owned(),
                detail: format!(
                    "anonymous member search exceeds {DESCENT_CAP} levels at type id {id}"
                ),
            });
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
                // T07-R2-02: the sought member's TYPE extent must
                // sit inside its immediate carrier (a nested member
                // that fits the root but escapes its carrier is
                // corrupt/drifted BTF — the read would chase an
                // adjacent word as the member).
                let extent = self.type_extent(mtype)?;
                let end = base
                    .checked_add(extent)
                    .ok_or_else(|| bad("member extent offset overflows".to_owned()))?;
                if end > rec.size_or_type {
                    return Err(bad(format!(
                        "member extent [{base}..{end}) escapes its {}-byte carrier",
                        rec.size_or_type
                    )));
                }
                return Ok(Some((base, mtype)));
            }
            if descend {
                // Anonymous member: descend into struct/union shapes
                // (through const/typedef wrappers), offsets add; the
                // LEAF type id propagates (the shape describes the
                // sought member, not the anonymous carrier).
                // (T07-R2-02: the carrier itself must sit inside its
                // parent — nesting proves at EVERY level, not just
                // the root.)
                if let Some(tid) = self.anon_target(mtype, member)? {
                    let carrier = self.rec(tid)?.size_or_type;
                    let carrier_end = base
                        .checked_add(carrier)
                        .ok_or_else(|| bad("anonymous carrier offset overflows".to_owned()))?;
                    if carrier_end > rec.size_or_type {
                        return Err(bad(format!(
                            "anonymous carrier [{base}..{carrier_end}) escapes its {}-byte parent",
                            rec.size_or_type
                        )));
                    }
                    if let Some((off, leaf)) = self.member_at(tid, member, depth + 1, path)? {
                        return Ok(Some((
                            base.checked_add(off).ok_or_else(|| {
                                bad("anonymous member offset overflows".to_owned())
                            })?,
                            leaf,
                        )));
                    }
                }
            }
        }
        Ok(None)
    }
}

/// Split-BTF view (P4): a module image resolved against its vmlinux
/// base. Module images from `/sys/kernel/btf/<module>` carry GLOBAL
/// (relocated) ids: ids below `start_id` address the base image, ids
/// at/above it address the module image at `id - start_id + 1`.
/// `start_id` is always `base.type_count() + 1`: module BTF is split
/// by kernel construction (a module BTF object cannot exist without
/// its vmlinux base).
///
/// String space is CONCATENATED (proven on live images: every named
/// record in the exposed `cryptd` image carries an offset at/above
/// the base `str_len`): offsets below the base `str_len` resolve in
/// the base strtab (shared names), offsets at/above it resolve in
/// the module strtab at `off - base_str_len`. Every name check
/// below routes through [`SplitBtf::module_str`] — a full-BTF module
/// (local offsets routed at the base) resolves DIFFERENT names and
/// refuses on mismatch, never misvalidates.
pub(crate) struct SplitBtf<'a, 'b, 'c, 'd> {
    base: &'a Btf<'b>,
    module: &'c Btf<'d>,
    start_id: u32,
}

/// One routed type record: the record plus the image that owns its
/// aux bytes and string references.
enum Routed<'x> {
    Base(&'x TypeRec),
    Module(&'x TypeRec),
}

impl SplitBtf<'_, '_, '_, '_> {
    /// New split view over an already-parsed base + module pair.
    pub(crate) fn new<'a, 'b, 'c, 'd>(
        base: &'a Btf<'b>,
        module: &'c Btf<'d>,
    ) -> SplitBtf<'a, 'b, 'c, 'd> {
        SplitBtf {
            base,
            module,
            start_id: base.type_count() + 1,
        }
    }

    /// Route one global id to its owning record (dangling ids —
    /// below 1 in either image, or past either image's end — are
    /// corrupt, never guessed).
    fn rec(&self, id: u32) -> Result<Routed<'_>, BtfError> {
        if id == 0 {
            return Err(bad("routed id 0 (VOID) names no record".to_owned()));
        }
        if id < self.start_id {
            self.base.rec(id).map(Routed::Base)
        } else {
            let local = id - self.start_id + 1;
            self.module.rec(local).map(Routed::Module)
        }
    }

    /// Chase qualifier wrappers to the first unwrapped GLOBAL type id
    /// (routed [`Btf::chase_wrappers`]: each step re-routes, since a
    /// module typedef may wrap a base type and vice versa).
    fn chase(&self, mut id: u32) -> Result<u32, BtfError> {
        let mut seen = [0u32; DESCENT_CAP + 1];
        for depth in 0..=DESCENT_CAP {
            if id == 0 {
                return Err(bad("wrapper chase reached VOID".to_owned()));
            }
            if seen[..depth].contains(&id) {
                return Err(bad("wrapper chase cycles".to_owned()));
            }
            seen[depth] = id;
            let (kind, size_or_type) = match self.rec(id)? {
                Routed::Base(rec) | Routed::Module(rec) => (rec.kind, rec.size_or_type),
            };
            match kind {
                KIND_TYPEDEF | KIND_CONST | KIND_VOLATILE | KIND_RESTRICT => {
                    id = size_or_type;
                }
                _ => return Ok(id),
            }
        }
        Err(bad("wrapper chase exceeds the descent cap".to_owned()))
    }

    /// One module-image string in concatenated space: offsets
    /// below the base `str_len` resolve in the BASE strtab (shared
    /// names — e.g. a module `INT "int"` reuses the base string),
    /// offsets at/above it resolve in the MODULE strtab (proven on
    /// the live `cryptd` image: all 75 named records sit at/above
    /// the base length). Out-of-range either way is corrupt BTF.
    fn module_str(&self, off: u32) -> Result<&[u8], BtfError> {
        let base_len = self.base.str_len();
        let off_usize = off as usize;
        if off_usize < base_len {
            self.base.str_at(off)
        } else {
            let local = off_usize - base_len;
            let local_u32 = u32::try_from(local)
                .map_err(|_| bad(format!("module string offset {off} out of range")))?;
            self.module
                .str_at(local_u32)
                .map_err(|_| bad(format!("module string offset {off} out of range")))
        }
    }

    /// Routed name check: base records resolve in the base strtab,
    /// module records in concatenated space.
    fn name_is(&self, id: u32, want: &str) -> Result<bool, BtfError> {
        match self.rec(id)? {
            Routed::Base(rec) => self.base.name_is(rec, want),
            Routed::Module(rec) => Ok(self.module_str(rec.name_off)? == want.as_bytes()),
        }
    }

    /// One aux word of a routed record, from the owning image.
    fn aux_u32(&self, id: u32, word: usize) -> Result<u32, BtfError> {
        match self.rec(id)? {
            Routed::Base(rec) => read_u32(self.base.bytes, rec.aux_at + word * 4, "routed aux"),
            Routed::Module(rec) => read_u32(self.module.bytes, rec.aux_at + word * 4, "routed aux"),
        }
    }

    /// Prove the routed `id` is a full 32-bit INT value at bit offset
    /// 0 (arg discipline mirrors [`Btf::int_arg_4` — bits + offset,
    /// encoding unpinned: the BPF copies/compares the raw u32).
    fn int_arg_4(&self, id: u32, arg: &str, name: &str) -> Result<(), BtfError> {
        let bad_proto = |reason: String| BtfError::BadPrototype {
            name: name.to_owned(),
            reason,
        };
        let id = self.chase(id)?;
        let (kind, size, data) = match self.rec(id)? {
            Routed::Base(rec) => (
                rec.kind,
                rec.size_or_type,
                read_u32(self.base.bytes, rec.aux_at, "int data")?,
            ),
            Routed::Module(rec) => (
                rec.kind,
                rec.size_or_type,
                read_u32(self.module.bytes, rec.aux_at, "int data")?,
            ),
        };
        if kind != KIND_INT {
            return Err(bad_proto(format!("{arg} is not an INT")));
        }
        if size != 4 {
            return Err(bad_proto(format!("{arg} INT is {size} bytes, not 4")));
        }
        let (bits, offset) = (data & 0xff, (data >> 16) & 0xff);
        if bits != 32 {
            return Err(bad_proto(format!("{arg} INT is {bits} bits, not 32")));
        }
        if offset != 0 {
            return Err(bad_proto(format!(
                "{arg} INT has bit offset {offset}, not 0"
            )));
        }
        Ok(())
    }

    /// First module-local `FUNC` id with `name`, globalized (module
    /// functions live only in the module image — the base is never
    /// scanned for them; names resolve in concatenated space, so the
    /// base-image [`Btf::func_id`] scan (base strtab only) cannot
    /// serve here).
    pub(crate) fn module_func_id(&self, name: &str) -> Result<Option<u32>, BtfError> {
        for (idx, rec) in self.module.types.iter().enumerate() {
            if rec.kind == KIND_FUNC && self.module_str(rec.name_off)? == name.as_bytes() {
                return Ok(Some(self.start_id + idx as u32));
            }
        }
        Ok(None)
    }

    /// First module-local STRUCT/UNION id with `name`, as a LOCAL id
    /// (module types live only in the module image; typedef-chased
    /// like [`Btf::find_struct`] but WITHOUT cross-image drift — the
    /// module image is scanned alone, names in concatenated space).
    fn module_struct(&self, name: &str) -> Result<u32, BtfError> {
        let mut found = None;
        for (idx, rec) in self.module.types.iter().enumerate() {
            let id = idx as u32 + 1;
            if (rec.kind == KIND_STRUCT || rec.kind == KIND_UNION)
                && self.module_str(rec.name_off)? == name.as_bytes()
            {
                found = Some(id);
                break;
            }
            if rec.kind == KIND_TYPEDEF && self.module_str(rec.name_off)? == name.as_bytes() {
                found = Some(id);
                break;
            }
        }
        match found {
            None => Err(BtfError::MissingType {
                name: name.to_owned(),
            }),
            Some(id) => {
                // Chase module-local typedefs to the STRUCT/UNION
                // (the chase stays module-local: a typedef at a base
                // id would refuse below, never drift across).
                let mut cur = id;
                for _ in 0..=DESCENT_CAP {
                    let rec = self.module.rec(cur)?;
                    match rec.kind {
                        KIND_TYPEDEF => {
                            cur = rec.size_or_type;
                        }
                        KIND_STRUCT | KIND_UNION => return Ok(cur),
                        _ => break,
                    }
                }
                Err(BtfError::MissingType {
                    name: name.to_owned(),
                })
            }
        }
    }

    /// Global FUNC id of `name` proven to be the cryptd shape `void
    /// (struct skcipher_request *, int, crypto_completion_t)`: exactly
    /// three arguments, arg0 a pointer at STRUCT `skcipher_request`
    /// whose pointee IS the caller-bound base entry id (T07-R4-N2 —
    /// the join keys on the same def the offsets resolver binds),
    /// arg1 a 32-bit INT (the native status), arg2 a pointer (the
    /// re-arm completion: pointer-ness pins the register shape, the
    /// pointee is NEVER validated — opaque to the adapter, mirroring
    /// setkey's key-buffer discipline), and a VOID return.
    pub(crate) fn cryptd_proto_id(&self, name: &str, sreq_entry: u32) -> Result<u32, BtfError> {
        let bad_proto = |reason: String| BtfError::BadPrototype {
            name: name.to_owned(),
            reason,
        };
        let id = self
            .module_func_id(name)?
            .ok_or_else(|| BtfError::MissingFunc {
                name: name.to_owned(),
            })?;
        let target = match self.rec(id)? {
            Routed::Base(rec) | Routed::Module(rec) => rec.size_or_type,
        };
        let vlen = match self.rec(target)? {
            Routed::Base(rec) | Routed::Module(rec) => {
                if rec.kind != KIND_FUNC_PROTO {
                    return Err(bad_proto(format!(
                        "FUNC target id {target} is kind {}, not FUNC_PROTO",
                        rec.kind
                    )));
                }
                rec.vlen
            }
        };
        if vlen != 3 {
            return Err(bad_proto(format!(
                "prototype takes {vlen} arguments, want exactly 3"
            )));
        }
        let arg0 = self.aux_u32(target, 1)?;
        let ptr = self.chase(arg0)?;
        if !matches!(self.rec(ptr)?, Routed::Base(rec) | Routed::Module(rec) if rec.kind == KIND_PTR)
        {
            return Err(bad_proto("arg0 is not a pointer".to_owned()));
        }
        let pointee = match self.rec(ptr)? {
            Routed::Base(rec) | Routed::Module(rec) => self.chase(rec.size_or_type)?,
        };
        if !matches!(self.rec(pointee)?, Routed::Base(rec) | Routed::Module(rec) if rec.kind == KIND_STRUCT)
        {
            return Err(bad_proto(
                "arg0 points at a non-STRUCT, not skcipher_request".to_owned(),
            ));
        }
        if !self.name_is(pointee, "skcipher_request")? {
            return Err(bad_proto(
                "arg0 points at the wrong STRUCT, not skcipher_request".to_owned(),
            ));
        }
        if pointee != sreq_entry {
            return Err(BtfError::IncompatibleDefinitions {
                type_name: "skcipher_request".to_owned(),
                entry_id: sreq_entry,
                linked_id: pointee,
                via: format!("{name}.arg0"),
            });
        }
        self.int_arg_4(self.aux_u32(target, 3)?, "arg1", name)?;
        let arg2 = self.aux_u32(target, 5)?;
        let arg2_chased = self.chase(arg2)?;
        if !matches!(self.rec(arg2_chased)?, Routed::Base(rec) | Routed::Module(rec) if rec.kind == KIND_PTR)
        {
            return Err(bad_proto("arg2 is not a pointer".to_owned()));
        }
        let ret = match self.rec(target)? {
            Routed::Base(rec) | Routed::Module(rec) => rec.size_or_type,
        };
        if ret != 0 {
            return Err(bad_proto("return is not VOID".to_owned()));
        }
        Ok(id)
    }

    /// Global FUNC id of `name` proven to be the fixture shape `void
    /// (void *, int)`: exactly two arguments, arg0 EXACTLY `void *`
    /// (a pointer at VOID — the consumer op; any typed pointer is
    /// drift, refused, never chased as data), arg1 a 32-bit INT
    /// (the native status), and a VOID return.
    pub(crate) fn kxc_proto_id(&self, name: &str) -> Result<u32, BtfError> {
        let bad_proto = |reason: String| BtfError::BadPrototype {
            name: name.to_owned(),
            reason,
        };
        let id = self
            .module_func_id(name)?
            .ok_or_else(|| BtfError::MissingFunc {
                name: name.to_owned(),
            })?;
        let target = match self.rec(id)? {
            Routed::Base(rec) | Routed::Module(rec) => rec.size_or_type,
        };
        let vlen = match self.rec(target)? {
            Routed::Base(rec) | Routed::Module(rec) => {
                if rec.kind != KIND_FUNC_PROTO {
                    return Err(bad_proto(format!(
                        "FUNC target id {target} is kind {}, not FUNC_PROTO",
                        rec.kind
                    )));
                }
                rec.vlen
            }
        };
        if vlen != 2 {
            return Err(bad_proto(format!(
                "prototype takes {vlen} arguments, want exactly 2"
            )));
        }
        let arg0 = self.aux_u32(target, 1)?;
        let ptr = self.chase(arg0)?;
        let pointee = match self.rec(ptr)? {
            Routed::Base(rec) | Routed::Module(rec) => {
                if rec.kind != KIND_PTR {
                    return Err(bad_proto("arg0 is not a pointer".to_owned()));
                }
                rec.size_or_type
            }
        };
        if pointee != 0 {
            return Err(bad_proto(
                "arg0 is not void * (typed op pointers are drift)".to_owned(),
            ));
        }
        self.int_arg_4(self.aux_u32(target, 3)?, "arg1", name)?;
        let ret = match self.rec(target)? {
            Routed::Base(rec) | Routed::Module(rec) => rec.size_or_type,
        };
        if ret != 0 {
            return Err(bad_proto("return is not VOID".to_owned()));
        }
        Ok(id)
    }

    /// Byte offset of the module STRUCT `kxc_op`'s DIRECT member `req`
    /// (no anonymous descent — the fixture owns this struct, so any
    /// nesting drift refuses): the member must prove a pointer at
    /// STRUCT `skcipher_request` whose pointee IS the caller-bound
    /// base entry id (T07-R4-N2), and the 8-byte pointer read must
    /// sit inside the struct (R4 containment — the BPF target is
    /// 64-bit, pointers read u64).
    pub(crate) fn kxc_op_req(&self, sk_entry: u32) -> Result<u32, BtfError> {
        let root = self.module_struct("kxc_op")?;
        let root_rec = self.module.rec(root)?;
        if !matches!(root_rec.kind, KIND_STRUCT | KIND_UNION) {
            return Err(BtfError::MissingType {
                name: "kxc_op".to_owned(),
            });
        }
        for m in 0..root_rec.vlen as usize {
            let at = root_rec.aux_at + m * 12;
            let name_off = read_u32(self.module.bytes, at, "member name_off")?;
            if name_off == 0 || self.module_str(name_off)? != b"req" {
                continue;
            }
            let mtype = read_u32(self.module.bytes, at + 4, "member type")?;
            let raw = read_u32(self.module.bytes, at + 8, "member offset")?;
            let bits = if root_rec.kind_flag {
                raw & 0x00ff_ffff
            } else {
                raw
            };
            let bitfield = root_rec.kind_flag && raw >> 24 != 0;
            if bitfield || !bits.is_multiple_of(8) {
                return Err(bad(format!(
                    "kxc_op.req at {at:#x} is not byte-aligned ({bits} bits)"
                )));
            }
            let off = bits / 8;
            let ptr = self.chase(mtype)?;
            let pointee = match self.rec(ptr)? {
                Routed::Base(rec) | Routed::Module(rec) => {
                    if rec.kind != KIND_PTR {
                        return Err(BtfError::BadPrototype {
                            name: "kxc_op.req".to_owned(),
                            reason: "member is not a pointer".to_owned(),
                        });
                    }
                    self.chase(rec.size_or_type)?
                }
            };
            if !matches!(self.rec(pointee)?, Routed::Base(rec) | Routed::Module(rec) if rec.kind == KIND_STRUCT)
            {
                return Err(BtfError::BadPrototype {
                    name: "kxc_op.req".to_owned(),
                    reason: "member points at a non-STRUCT, not skcipher_request".to_owned(),
                });
            }
            if !self.name_is(pointee, "skcipher_request")? {
                return Err(BtfError::BadPrototype {
                    name: "kxc_op.req".to_owned(),
                    reason: "member points at the wrong STRUCT, not skcipher_request".to_owned(),
                });
            }
            if pointee != sk_entry {
                return Err(BtfError::IncompatibleDefinitions {
                    type_name: "skcipher_request".to_owned(),
                    entry_id: sk_entry,
                    linked_id: pointee,
                    via: "kxc_op.req".to_owned(),
                });
            }
            let end = off
                .checked_add(8)
                .ok_or_else(|| bad("kxc_op.req read offset overflows".to_owned()))?;
            if end > root_rec.size_or_type {
                return Err(bad(format!(
                    "kxc_op.req read [{off}..{end}) escapes the {}-byte parent",
                    root_rec.size_or_type
                )));
            }
            return Ok(off);
        }
        Err(BtfError::MissingMember {
            type_name: "kxc_op".to_owned(),
            member: "req".to_owned(),
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal hermetic BTF image builder (R4: counter-leaf and
    /// containment regressions without the object-fixture block).
    struct Img {
        types: Vec<u8>,
        strs: Vec<u8>,
        next_id: u32,
        str_bias: u32,
    }

    impl Img {
        fn new() -> Self {
            Self {
                types: Vec::new(),
                strs: vec![0],
                next_id: 1,
                str_bias: 0,
            }
        }

        /// Split-module image: emitted name offsets bias by the base
        /// `str_len` (concatenated string space — the image's own
        /// strtab section still starts at its local 0).
        fn new_split(str_bias: u32) -> Self {
            Self {
                types: Vec::new(),
                strs: vec![0],
                next_id: 1,
                str_bias,
            }
        }

        /// Anonymous name offset (always literal 0, never biased).
        fn anon(&self) -> u32 {
            0
        }

        fn str(&mut self, s: &str) -> u32 {
            let off = self.strs.len() as u32;
            self.strs.extend_from_slice(s.as_bytes());
            self.strs.push(0);
            self.str_bias + off
        }

        fn rec(
            &mut self,
            name_off: u32,
            kind: u8,
            vlen: u32,
            size_or_type: u32,
            aux: &[u8],
        ) -> u32 {
            let id = self.next_id;
            self.next_id += 1;
            let info = ((kind as u32) << 24) | (vlen & 0xffff);
            self.types.extend_from_slice(&name_off.to_le_bytes());
            self.types.extend_from_slice(&info.to_le_bytes());
            self.types.extend_from_slice(&size_or_type.to_le_bytes());
            self.types.extend_from_slice(aux);
            id
        }

        fn int(&mut self, name: &str, size: u32) -> u32 {
            // Realistic kernel encoding: full width, zero offset
            // (signed iff the name says `int` — pahole-shape-exact;
            // the T07-R2-01 adversarial shapes use `int_enc`).
            let encoding = if name == "int" { 1u32 } else { 0u32 };
            self.int_enc(name, size, size * 8, 0, encoding)
        }

        /// INT with explicit encoding: storage `size` bytes, value
        /// `bits` wide at bit `offset` (T07-R2-01 adversarial
        /// shapes: narrowed/shifted values in 4-byte storage).
        fn int_enc(&mut self, name: &str, size: u32, bits: u32, offset: u32, encoding: u32) -> u32 {
            let name_off = self.str(name);
            // INT aux: bits[0..8) + offset[16..24) + encoding[24..28).
            let data = (bits & 0xff) | ((offset & 0xff) << 16) | ((encoding & 0x0f) << 24);
            self.rec(name_off, KIND_INT, 0, size, &data.to_le_bytes())
        }

        fn member_aux(name_off: u32, mtype: u32, bit_off: u32) -> [u8; 12] {
            let mut out = [0u8; 12];
            out[0..4].copy_from_slice(&name_off.to_le_bytes());
            out[4..8].copy_from_slice(&mtype.to_le_bytes());
            out[8..12].copy_from_slice(&bit_off.to_le_bytes());
            out
        }

        fn image(&self) -> Vec<u8> {
            let mut out = vec![0u8; 24];
            out[0..2].copy_from_slice(&BTF_MAGIC.to_le_bytes());
            out[2] = BTF_VERSION;
            out[4..8].copy_from_slice(&24u32.to_le_bytes());
            out[8..12].copy_from_slice(&0u32.to_le_bytes());
            out[12..16].copy_from_slice(&(self.types.len() as u32).to_le_bytes());
            out[16..20].copy_from_slice(&(self.types.len() as u32).to_le_bytes());
            out[20..24].copy_from_slice(&(self.strs.len() as u32).to_le_bytes());
            out.extend_from_slice(&self.types);
            out.extend_from_slice(&self.strs);
            out
        }
    }

    /// Bind `name` the way the resolver does (T07-R3-09: one
    /// [`Btf::find_struct`] bind per entry name, ids threaded — these
    /// fixtures carry a single def per name, so the bind is trivial).
    fn bind(btf: &Btf, name: &str) -> u32 {
        btf.find_struct(name).expect("fixture binds")
    }

    /// `crypto_tfm` (size 8) with a plain-u32 `refcnt` at byte 4
    /// (boundary-contained: 4 + 4 == 8).
    fn tfm_with_u32_refcnt() -> Vec<u8> {
        let mut img = Img::new();
        let u32_id = img.int("unsigned int", 4);
        let tfm_name = img.str("crypto_tfm");
        let refcnt_name = img.str("refcnt");
        let aux = Img::member_aux(refcnt_name, u32_id, 4 * 8);
        img.rec(tfm_name, KIND_STRUCT, 1, 8, &aux);
        img.image()
    }

    #[test]
    fn r4_plain_u32_counter_accepts_at_boundary() {
        let bytes = tfm_with_u32_refcnt();
        let btf = Btf::parse(&bytes).expect("fixture parses");
        assert_eq!(
            btf.member_counter_in(bind(&btf, "crypto_tfm"), "crypto_tfm", "refcnt")
                .expect("u32 counter"),
            4
        );
    }

    #[test]
    fn r4_wider_int_counter_refuses() {
        // A 64-bit counter reads a lying low word (0x1_0000_0001).
        let mut img = Img::new();
        let u64_id = img.int("unsigned long", 8);
        let tfm_name = img.str("crypto_tfm");
        let refcnt_name = img.str("refcnt");
        let aux = Img::member_aux(refcnt_name, u64_id, 0);
        img.rec(tfm_name, KIND_STRUCT, 1, 8, &aux);
        let bytes = img.image();
        let btf = Btf::parse(&bytes).expect("fixture parses");
        assert!(
            btf.member_counter_in(bind(&btf, "crypto_tfm"), "crypto_tfm", "refcnt")
                .is_err(),
            "u64 counter must refuse"
        );
    }

    #[test]
    fn r4_refcount_nesting_accepts() {
        // The real kernel chain: refcount_t { atomic_t refs; } (4B)
        // → atomic_t { int counter; } (4B) → int (4B).
        let mut img = Img::new();
        let int_id = img.int("int", 4);
        let atomic_name = img.str("atomic_t");
        let counter_name = img.str("counter");
        let aux = Img::member_aux(counter_name, int_id, 0);
        let atomic_id = img.rec(atomic_name, KIND_STRUCT, 1, 4, &aux);
        let refcount_name = img.str("refcount_t");
        let refs_name = img.str("refs");
        let aux = Img::member_aux(refs_name, atomic_id, 0);
        let refcount_id = img.rec(refcount_name, KIND_STRUCT, 1, 4, &aux);
        let tfm_name = img.str("crypto_tfm");
        let refcnt_name = img.str("refcnt");
        let aux = Img::member_aux(refcnt_name, refcount_id, 0);
        img.rec(tfm_name, KIND_STRUCT, 1, 4, &aux);
        let bytes = img.image();
        let btf = Btf::parse(&bytes).expect("fixture parses");
        assert_eq!(
            btf.member_counter_in(bind(&btf, "crypto_tfm"), "crypto_tfm", "refcnt")
                .expect("refcount_t chain"),
            0
        );
    }

    #[test]
    fn r4_marker_before_counter_refuses() {
        // A changed wrapper with a marker word before the counter
        // (8 bytes — the first word's meaning is unproven).
        let mut img = Img::new();
        let int_id = img.int("int", 4);
        let wrap_name = img.str("wrapped_refc");
        let marker_name = img.str("marker");
        let refs_name = img.str("refs");
        let mut aux = Vec::new();
        aux.extend_from_slice(&Img::member_aux(marker_name, int_id, 0));
        aux.extend_from_slice(&Img::member_aux(refs_name, int_id, 4 * 8));
        let wrap_id = img.rec(wrap_name, KIND_STRUCT, 2, 8, &aux);
        let tfm_name = img.str("crypto_tfm");
        let refcnt_name = img.str("refcnt");
        let aux = Img::member_aux(refcnt_name, wrap_id, 0);
        img.rec(tfm_name, KIND_STRUCT, 1, 8, &aux);
        let bytes = img.image();
        let btf = Btf::parse(&bytes).expect("fixture parses");
        assert!(
            btf.member_counter_in(bind(&btf, "crypto_tfm"), "crypto_tfm", "refcnt")
                .is_err(),
            "marker-first wrapper must refuse"
        );
    }

    #[test]
    fn r4_counter_outside_parent_refuses() {
        // Corrupt/drifted BTF: the 4-byte read escapes the parent.
        let mut img = Img::new();
        let u32_id = img.int("unsigned int", 4);
        let tfm_name = img.str("crypto_tfm");
        let refcnt_name = img.str("refcnt");
        let aux = Img::member_aux(refcnt_name, u32_id, 4 * 8);
        img.rec(tfm_name, KIND_STRUCT, 1, 4, &aux);
        let bytes = img.image();
        let btf = Btf::parse(&bytes).expect("fixture parses");
        let err = btf
            .member_counter_in(bind(&btf, "crypto_tfm"), "crypto_tfm", "refcnt")
            .expect_err("escaping read must refuse");
        assert!(
            format!("{err:?}").contains("escapes"),
            "names containment: {err:?}"
        );
    }

    #[test]
    fn r4_shifted_or_narrow_int_counter_refuses() {
        // T07-R2-01: 4-byte storage proves nothing alone — a
        // shifted 16-bit value (offset 16) or a narrow 16-bit
        // value (offset 0) in a 4-byte container must refuse:
        // the BPF reads the full u32, not the value.
        for (bits, offset, why) in [(16u32, 16u32, "shifted"), (16, 0, "narrow")] {
            let mut img = Img::new();
            let v16_id = img.int_enc("narrow_t", 4, bits, offset, 0);
            let tfm_name = img.str("crypto_tfm");
            let refcnt_name = img.str("refcnt");
            let aux = Img::member_aux(refcnt_name, v16_id, 0);
            img.rec(tfm_name, KIND_STRUCT, 1, 8, &aux);
            let bytes = img.image();
            let btf = Btf::parse(&bytes).expect("fixture parses");
            let err = btf
                .member_counter_in(bind(&btf, "crypto_tfm"), "crypto_tfm", "refcnt")
                .expect_err("narrow/shifted counter must refuse");
            assert!(
                format!("{err:?}").contains("bits") || format!("{err:?}").contains("offset"),
                "{why} names the encoding: {err:?}"
            );
        }
    }

    #[test]
    fn r4_shifted_leaf_counter_refuses() {
        // T07-R2-01 nested arm: the refcount_t-shaped wrapper
        // with a shifted 16-bit leaf INT refuses — the leaf
        // proof is VALUE width, not storage width.
        let mut img = Img::new();
        let leaf_id = img.int_enc("shifted_counter", 4, 16, 16, 0);
        let atomic_name = img.str("atomic_t");
        let counter_name = img.str("counter");
        let aux = Img::member_aux(counter_name, leaf_id, 0);
        let atomic_id = img.rec(atomic_name, KIND_STRUCT, 1, 4, &aux);
        let tfm_name = img.str("crypto_tfm");
        let refcnt_name = img.str("refcnt");
        let aux = Img::member_aux(refcnt_name, atomic_id, 0);
        img.rec(tfm_name, KIND_STRUCT, 1, 4, &aux);
        let bytes = img.image();
        let btf = Btf::parse(&bytes).expect("fixture parses");
        assert!(
            btf.member_counter_in(bind(&btf, "crypto_tfm"), "crypto_tfm", "refcnt")
                .is_err(),
            "shifted leaf must refuse"
        );
    }

    #[test]
    fn r4_nested_carrier_escape_refuses() {
        // T07-R2-02: a purported 8-byte pointer at carrier offset
        // 8 inside a 4-byte anonymous carrier, inside a 64-byte
        // root — fits the root, escapes the carrier: the read
        // would chase an adjacent word as the member.
        let mut img = Img::new();
        let pointee_name = img.str("crypto_alg");
        let pointee_id = img.rec(pointee_name, KIND_STRUCT, 0, 64, &[]);
        let anon_off = img.str("");
        let ptr_id = img.rec(anon_off, KIND_PTR, 0, pointee_id, &[]);
        let carrier_name = img.str("carrier");
        let p_name = img.str("p");
        let aux = Img::member_aux(p_name, ptr_id, 8 * 8);
        let carrier_id = img.rec(carrier_name, KIND_STRUCT, 1, 4, &aux);
        let root_name = img.str("root");
        let aux = Img::member_aux(0, carrier_id, 0);
        img.rec(root_name, KIND_STRUCT, 1, 64, &aux);
        let bytes = img.image();
        let btf = Btf::parse(&bytes).expect("fixture parses");
        let err = btf
            .member_ptr_target_in(bind(&btf, "root"), "root", "p", "crypto_alg")
            .expect_err("carrier escape must refuse");
        assert!(
            format!("{err:?}").contains("escapes its 4-byte carrier"),
            "names the carrier: {err:?}"
        );
        // Contained twin: a 16-byte anonymous carrier with the
        // pointer at carrier offset 8 still resolves (the proof
        // refuses escapes, not nesting).
        let mut img = Img::new();
        let pointee_name = img.str("crypto_alg");
        let pointee_id = img.rec(pointee_name, KIND_STRUCT, 0, 64, &[]);
        let anon_off = img.str("");
        let ptr_id = img.rec(anon_off, KIND_PTR, 0, pointee_id, &[]);
        let carrier_name = img.str("carrier");
        let p_name = img.str("p");
        let aux = Img::member_aux(p_name, ptr_id, 8 * 8);
        let carrier_id = img.rec(carrier_name, KIND_STRUCT, 1, 16, &aux);
        let root_name = img.str("root");
        let aux = Img::member_aux(0, carrier_id, 0);
        img.rec(root_name, KIND_STRUCT, 1, 64, &aux);
        let bytes = img.image();
        let btf = Btf::parse(&bytes).expect("fixture parses");
        assert_eq!(
            btf.member_ptr_target_in(bind(&btf, "root"), "root", "p", "crypto_alg")
                .map(|(off, _)| off)
                .expect("contained nesting resolves"),
            8
        );
    }

    #[test]
    fn r4_empty_embedded_refuses() {
        // T07-R2-02: a zero-size embedded struct proves no extent
        // — further offsets would add past it.
        let mut img = Img::new();
        let base_name = img.str("crypto_tfm");
        let base_id = img.rec(base_name, KIND_STRUCT, 0, 0, &[]);
        let sk_name = img.str("crypto_skcipher");
        let member_name = img.str("base");
        let aux = Img::member_aux(member_name, base_id, 0);
        img.rec(sk_name, KIND_STRUCT, 1, 8, &aux);
        let bytes = img.image();
        let btf = Btf::parse(&bytes).expect("fixture parses");
        assert!(
            btf.member_embedded_target_in(
                bind(&btf, "crypto_skcipher"),
                "crypto_skcipher",
                "base",
                "crypto_tfm"
            )
            .is_err(),
            "empty embedded must refuse"
        );
    }

    #[test]
    fn r3_narrow_byte_element_name_refuses() {
        // T07-R3-06: a 1-byte container with a 4-bit value is not a
        // byte the BPF can copy as a driver-name char — the
        // element encoding must prove 8-bit zero-offset, like
        // every other lifecycle read.
        let mut img = Img::new();
        let narrow = img.int_enc("narrow_char", 1, 4, 0, 0);
        let u32_id = img.int_enc("unsigned int", 4, 32, 0, 0);
        let mut aux = [0u8; 12];
        aux[0..4].copy_from_slice(&narrow.to_le_bytes());
        aux[4..8].copy_from_slice(&u32_id.to_le_bytes());
        aux[8..12].copy_from_slice(&64u32.to_le_bytes());
        let arr_name = img.str("");
        let arr_id = img.rec(arr_name, KIND_ARRAY, 0, 0, &aux);
        let alg_name = img.str("crypto_alg");
        let drv_name = img.str("cra_driver_name");
        let maux = Img::member_aux(drv_name, arr_id, 188 * 8);
        img.rec(alg_name, KIND_STRUCT, 1, 256, &maux);
        let bytes = img.image();
        let btf = Btf::parse(&bytes).expect("fixture parses");
        assert!(
            btf.member_bytes_in(
                bind(&btf, "crypto_alg"),
                "crypto_alg",
                "cra_driver_name",
                64
            )
            .is_err(),
            "4-bit elements are not copyable bytes"
        );
    }

    #[test]
    fn r3_union_counter_views_must_agree() {
        // T07-R3-08: overlapping counter views must ALL prove,
        // regardless of member order — a full-width alias must not
        // launder a shifted sibling (and order must not decide).
        for raw_first in [true, false] {
            let mut img = Img::new();
            let raw = img.int_enc("unsigned int", 4, 32, 0, 0);
            let narrow = img.int_enc("narrow_t", 4, 16, 16, 0);
            let (a, b) = if raw_first {
                (raw, narrow)
            } else {
                (narrow, raw)
            };
            let v0 = img.str("v0");
            let v1 = img.str("v1");
            let mut aux = [0u8; 24];
            let (m0, m1) = (Img::member_aux(v0, a, 0), Img::member_aux(v1, b, 0));
            aux[0..12].copy_from_slice(&m0);
            aux[12..24].copy_from_slice(&m1);
            let u_name = img.str("counter_u");
            let u_id = img.rec(u_name, KIND_UNION, 2, 4, &aux);
            let tfm_name = img.str("crypto_tfm");
            let refcnt_name = img.str("refcnt");
            let maux = Img::member_aux(refcnt_name, u_id, 0);
            img.rec(tfm_name, KIND_STRUCT, 1, 8, &maux);
            let bytes = img.image();
            let btf = Btf::parse(&bytes).expect("fixture parses");
            assert!(
                btf.member_counter_in(bind(&btf, "crypto_tfm"), "crypto_tfm", "refcnt")
                    .is_err(),
                "raw_first={raw_first}: shifted sibling must refuse"
            );
        }
    }

    #[test]
    fn r4_pointer_and_embedded_outside_parent_refuse() {
        // member_ptr_target_in (8-byte read) and
        // member_embedded_target_in (full extent) prove containment.
        let mut img = Img::new();
        let pointee_name = img.str("crypto_alg");
        let pointee_id = img.rec(pointee_name, KIND_STRUCT, 0, 64, &[]);
        let ptr_name = img.str("");
        let ptr_id = img.rec(ptr_name, KIND_PTR, 0, pointee_id, &[]);
        let tfm_name = img.str("crypto_tfm");
        let alg_name = img.str("__crt_alg");
        let aux = Img::member_aux(alg_name, ptr_id, 4 * 8);
        img.rec(tfm_name, KIND_STRUCT, 1, 8, &aux);
        let bytes = img.image();
        let btf = Btf::parse(&bytes).expect("fixture parses");
        assert!(
            btf.member_ptr_target_in(
                bind(&btf, "crypto_tfm"),
                "crypto_tfm",
                "__crt_alg",
                "crypto_alg"
            )
            .is_err(),
            "pointer read [4..12) escapes the 8-byte parent"
        );
        // Contained twin (16-byte parent) passes the same proof.
        let mut img = Img::new();
        let pointee_name = img.str("crypto_alg");
        let pointee_id = img.rec(pointee_name, KIND_STRUCT, 0, 64, &[]);
        let ptr_name = img.str("");
        let ptr_id = img.rec(ptr_name, KIND_PTR, 0, pointee_id, &[]);
        let tfm_name = img.str("crypto_tfm");
        let alg_name = img.str("__crt_alg");
        let aux = Img::member_aux(alg_name, ptr_id, 4 * 8);
        img.rec(tfm_name, KIND_STRUCT, 1, 16, &aux);
        let bytes = img.image();
        let btf = Btf::parse(&bytes).expect("fixture parses");
        assert_eq!(
            btf.member_ptr_target_in(
                bind(&btf, "crypto_tfm"),
                "crypto_tfm",
                "__crt_alg",
                "crypto_alg"
            )
            .map(|(off, _)| off)
            .expect("contained pointer"),
            4
        );
        // Embedded extent escaping the parent refuses too (a 16-byte
        // `base` at 8 inside a 16-byte parent).
        let mut img = Img::new();
        let base_name = img.str("crypto_tfm");
        let base_id = img.rec(base_name, KIND_STRUCT, 0, 16, &[]);
        let sk_name = img.str("crypto_skcipher");
        let member_name = img.str("base");
        let aux = Img::member_aux(member_name, base_id, 8 * 8);
        img.rec(sk_name, KIND_STRUCT, 1, 16, &aux);
        let bytes = img.image();
        let btf = Btf::parse(&bytes).expect("fixture parses");
        assert!(
            btf.member_embedded_target_in(
                bind(&btf, "crypto_skcipher"),
                "crypto_skcipher",
                "base",
                "crypto_tfm"
            )
            .is_err(),
            "embedded extent [8..24) escapes the 16-byte parent"
        );
    }

    /// Split-BTF base: `skcipher_request` (id 1) + signed `int` (id
    /// 2) — every module ref below `start_id` (= 3) routes here.
    fn split_base() -> Vec<u8> {
        let mut img = Img::new();
        let sreq = img.str("skcipher_request");
        img.rec(sreq, KIND_STRUCT, 0, 64, &[]);
        img.int("int", 4);
        img.image()
    }

    fn proto_aux(args: &[(u32, u32)]) -> Vec<u8> {
        let mut aux = Vec::new();
        for (name_off, ty) in args {
            aux.extend_from_slice(&name_off.to_le_bytes());
            aux.extend_from_slice(&ty.to_le_bytes());
        }
        aux
    }

    /// Module side of the cryptd shape: PTR→base-skcipher_request,
    /// `crypto_completion_t` typedef→that PTR, the 3-arg proto, the
    /// FUNC. Global ids assume the 2-record base above.
    fn split_module_cryptd(bias: u32) -> Vec<u8> {
        let mut img = Img::new_split(bias);
        let anon = img.anon();
        let ptr = img.rec(anon, KIND_PTR, 0, 1, &[]);
        assert_eq!(ptr, 1);
        let compl = img.str("crypto_completion_t");
        img.rec(compl, KIND_TYPEDEF, 0, 3, &[]);
        let proto = img.str("");
        let aux = proto_aux(&[(0, 3), (0, 2), (0, 4)]);
        img.rec(proto, KIND_FUNC_PROTO, 3, 0, &aux);
        let func = img.str("cryptd_skcipher_complete");
        img.rec(func, KIND_FUNC, 0, 5, &[]);
        img.image()
    }

    /// Module side of the fixture shape: `void *`, the 2-arg proto,
    /// the FUNC, PTR→base-skcipher_request, and `kxc_op` with
    /// `(run, tfm, req)` at (0, 8, 16).
    fn split_module_kxc(bias: u32) -> Vec<u8> {
        let mut img = Img::new_split(bias);
        let anon = img.anon();
        let voidptr = img.rec(anon, KIND_PTR, 0, 0, &[]);
        assert_eq!(voidptr, 1);
        let aux = proto_aux(&[(0, 3), (0, 2)]);
        img.rec(anon, KIND_FUNC_PROTO, 2, 0, &aux);
        let func = img.str("kxc_complete");
        img.rec(func, KIND_FUNC, 0, 4, &[]);
        img.rec(anon, KIND_PTR, 0, 1, &[]);
        let op = img.str("kxc_op");
        let run = img.str("run");
        let tfm = img.str("tfm");
        let req = img.str("req");
        let mut aux = Vec::new();
        aux.extend_from_slice(&Img::member_aux(run, 6, 0));
        aux.extend_from_slice(&Img::member_aux(tfm, 6, 8 * 8));
        aux.extend_from_slice(&Img::member_aux(req, 6, 16 * 8));
        img.rec(op, KIND_STRUCT, 3, 24, &aux);
        img.image()
    }

    #[test]
    fn split_cryptd_shape_validates_across_images() {
        let base_bytes = split_base();
        let base = Btf::parse(&base_bytes).expect("base parses");
        let module = split_module_cryptd(base.str_len() as u32);
        let module = Btf::parse(&module).expect("module parses");
        let split = SplitBtf::new(&base, &module);
        // Module FUNC is local id 4 → global 3 + 4 - 1 = 6.
        assert_eq!(
            split
                .cryptd_proto_id("cryptd_skcipher_complete", 1)
                .expect("cryptd shape"),
            6
        );
    }

    #[test]
    fn split_kxc_shape_and_op_req_validate() {
        let base_bytes = split_base();
        let base = Btf::parse(&base_bytes).expect("base parses");
        let module = split_module_kxc(base.str_len() as u32);
        let module = Btf::parse(&module).expect("module parses");
        let split = SplitBtf::new(&base, &module);
        assert_eq!(split.kxc_proto_id("kxc_complete").expect("kxc shape"), 5);
        assert_eq!(split.kxc_op_req(1).expect("op->req"), 16);
    }

    #[test]
    fn split_rival_skcipher_request_refuses_r4n2() {
        // A module-local STRUCT `skcipher_request` (dedup drift):
        // arg0 resolving at the module def instead of the bound
        // base entry refuses — the join must key on one def.
        let base_bytes = split_base();
        let base = Btf::parse(&base_bytes).expect("base parses");
        let mut img = Img::new_split(base.str_len() as u32);
        let anon = img.anon();
        let rival = img.str("skcipher_request");
        img.rec(rival, KIND_STRUCT, 0, 64, &[]);
        img.rec(anon, KIND_PTR, 0, 3, &[]);
        let compl = img.str("crypto_completion_t");
        img.rec(compl, KIND_TYPEDEF, 0, 4, &[]);
        let aux = proto_aux(&[(0, 4), (0, 2), (0, 5)]);
        img.rec(anon, KIND_FUNC_PROTO, 3, 0, &aux);
        let func = img.str("cryptd_skcipher_complete");
        img.rec(func, KIND_FUNC, 0, 6, &[]);
        let mbytes = img.image();
        let module = Btf::parse(&mbytes).expect("module parses");
        let split = SplitBtf::new(&base, &module);
        let err = split
            .cryptd_proto_id("cryptd_skcipher_complete", 1)
            .expect_err("rival def must refuse");
        assert!(
            matches!(err, BtfError::IncompatibleDefinitions { .. }),
            "names the rival def: {err:?}"
        );
    }

    #[test]
    fn split_op_req_drift_refuses() {
        let base_bytes = split_base();
        let base = Btf::parse(&base_bytes).expect("base parses");
        // Missing `req` member.
        let mut img = Img::new_split(base.str_len() as u32);
        let anon = img.anon();
        let op = img.str("kxc_op");
        let run = img.str("run");
        img.rec(anon, KIND_PTR, 0, 1, &[]);
        let aux = Img::member_aux(run, 3, 0);
        img.rec(op, KIND_STRUCT, 1, 8, &aux);
        let mbytes = img.image();
        let module = Btf::parse(&mbytes).expect("module parses");
        let split = SplitBtf::new(&base, &module);
        assert!(
            matches!(split.kxc_op_req(1), Err(BtfError::MissingMember { .. })),
            "missing req refuses"
        );
        // `req` at the wrong pointee (base INT, not a STRUCT).
        let mut img = Img::new_split(base.str_len() as u32);
        let anon = img.anon();
        let op = img.str("kxc_op");
        let req = img.str("req");
        img.rec(anon, KIND_PTR, 0, 2, &[]);
        let aux = Img::member_aux(req, 3, 0);
        img.rec(op, KIND_STRUCT, 1, 8, &aux);
        let mbytes = img.image();
        let module = Btf::parse(&mbytes).expect("module parses");
        let split = SplitBtf::new(&base, &module);
        assert!(
            matches!(split.kxc_op_req(1), Err(BtfError::BadPrototype { .. })),
            "wrong pointee refuses"
        );
    }

    #[test]
    fn split_strings_route_concatenated_space() {
        // Offsets below the base length resolve in the BASE
        // strtab (shared names); at/above it, in the MODULE
        // strtab (live cryptd image: all 75 named records).
        let base_bytes = split_base();
        let base = Btf::parse(&base_bytes).expect("base parses");
        let mbytes = split_module_kxc(base.str_len() as u32);
        let module = Btf::parse(&mbytes).expect("module parses");
        let split = SplitBtf::new(&base, &module);
        assert_eq!(
            split.module_str(1).expect("base string"),
            b"skcipher_request"
        );
        let bias = base.str_len() as u32;
        assert_eq!(split.module_str(bias).expect("module empty"), b"");
        assert!(split.module_str(u32::MAX).is_err(), "wild offset refuses");
    }

    #[test]
    fn split_proto_drift_refuses() {
        let base_bytes = split_base();
        let base = Btf::parse(&base_bytes).expect("base parses");
        // kxc arg0 retyped (PTR at base STRUCT, not void *).
        let mut img = Img::new_split(base.str_len() as u32);
        let anon = img.anon();
        img.rec(anon, KIND_PTR, 0, 1, &[]);
        let aux = proto_aux(&[(0, 3), (0, 2)]);
        img.rec(anon, KIND_FUNC_PROTO, 2, 0, &aux);
        let func = img.str("kxc_complete");
        img.rec(func, KIND_FUNC, 0, 4, &[]);
        let mbytes = img.image();
        let module = Btf::parse(&mbytes).expect("module parses");
        let split = SplitBtf::new(&base, &module);
        assert!(
            matches!(
                split.kxc_proto_id("kxc_complete"),
                Err(BtfError::BadPrototype { .. })
            ),
            "typed arg0 refuses"
        );
        // Missing function.
        let mbytes = split_module_kxc(base.str_len() as u32);
        let module = Btf::parse(&mbytes).expect("module parses");
        let split = SplitBtf::new(&base, &module);
        assert!(
            matches!(
                split.kxc_proto_id("kxc_nope"),
                Err(BtfError::MissingFunc { .. })
            ),
            "missing func refuses"
        );
    }
}
