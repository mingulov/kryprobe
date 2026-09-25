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
        Ok(id)
    }

    /// Validate that `name`'s prototype is EXACTLY the qualified
    /// allocation-sensor read — `struct crypto_skcipher *(const char
    /// *, u32, u32)` — and return its `FUNC` id (T07.2, same
    /// refuse-on-drift discipline as [`Btf::lifecycle_proto_id`]):
    /// exactly three arguments, arg0 a pointer (after qualifier
    /// chase) to 1-byte INT (`char` — the bounded name copy reads
    /// raw bytes, so the width pins but the signedness does not),
    /// arg1/arg2 4-byte INTs (the type/mask words travel as unshifted
    /// `u32` copies — the width pins, the encoding does not), return
    /// a pointer to STRUCT `crypto_skcipher` (the success chase reads
    /// `__crt_alg` at the resolved offset — a pointer to any other
    /// type would mis-chase). Corrupt images stay
    /// [`BtfError::BadBtf`]; well-formed but incompatible prototypes
    /// are [`BtfError::BadPrototype`].
    pub(crate) fn alloc_proto_id(&self, name: &str) -> Result<u32, BtfError> {
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
        // chases: it must point at STRUCT `crypto_skcipher`.
        let ret = proto.size_or_type;
        if ret == 0 {
            return Err(bad_proto("return is VOID, not a tfm pointer".to_owned()));
        }
        let rec = self.rec(self.chase_wrappers(ret)?)?;
        if rec.kind != KIND_PTR {
            return Err(bad_proto("return is not a pointer".to_owned()));
        }
        let pointee = self.rec(self.chase_wrappers(rec.size_or_type)?)?;
        if pointee.kind != KIND_STRUCT {
            return Err(bad_proto(format!(
                "return points at kind {}, not STRUCT crypto_skcipher",
                pointee.kind
            )));
        }
        if !self.name_is(pointee, "crypto_skcipher")? {
            return Err(bad_proto(
                "return points at the wrong STRUCT, not crypto_skcipher".to_owned(),
            ));
        }
        Ok(id)
    }

    /// FUNC id of `name` proven to be the destroy shape
    /// `void (void *, struct crypto_tfm *)` (T07.3): exactly two
    /// args, arg0 a pointer (the frontend `mem` — pointee
    /// unchecked: any pointer-typed arg0 carries the frontend
    /// address, and the tracker classifies null/ERR as a no-op
    /// release), arg1 a pointer at STRUCT `crypto_tfm` (the
    /// refcount read lands in it — a wrong pointee would read a
    /// stranger's word as a refcount), and a VOID return (the
    /// exit run emits no status — reading a return register from
    /// a void call would emit garbage as truth).
    pub(crate) fn destroy_proto_id(&self, name: &str) -> Result<u32, BtfError> {
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
        let pointee = self.rec(self.chase_wrappers(tfm.size_or_type)?)?;
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
        Ok(id)
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

    /// Prove the FUNC_PROTO argument at `at` is a 4-byte INT (the
    /// T07.4 length gate): scalar length words travel as unshifted
    /// `u32` copies — the width pins, the signedness does not (a
    /// wider scalar would truncate, a non-scalar would misread).
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
        Ok(())
    }

    /// FUNC id of `name` proven to be the setkey shape
    /// `int (<frontend> *, const u8 *, unsigned int)` (T07.4):
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
    pub(crate) fn setkey_proto_id(&self, name: &str, frontend: &str) -> Result<u32, BtfError> {
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
        let pointee = self.rec(self.chase_wrappers(ptr.size_or_type)?)?;
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
        Ok(id)
    }

    /// FUNC id of `name` proven to be the setauthsize shape
    /// `int (struct crypto_aead *, unsigned int)` (T07.4): exactly
    /// two arguments, arg0 a pointer at STRUCT `crypto_aead` (the
    /// joined transform identity), arg1 a 4-byte INT (the authsize),
    /// and a SIGNED 32-bit INT return (the errno). Same
    /// refuse-on-drift discipline as [`Btf::setkey_proto_id`].
    pub(crate) fn setauthsize_proto_id(&self, name: &str) -> Result<u32, BtfError> {
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
        let pointee = self.rec(self.chase_wrappers(ptr.size_or_type)?)?;
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
        Ok(id)
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
        let mut path = [0u32; DESCENT_CAP + 1];
        self.member_at(root, member, 0, &mut path)?
            .ok_or_else(|| BtfError::MissingMember {
                type_name: type_name.to_owned(),
                member: member.to_owned(),
            })
    }

    /// Offset of `member` proven to be a pointer at STRUCT/UNION
    /// `pointee` (wrappers chased on both sides): the BPF chase may
    /// dereference it and read the pointee at further resolved
    /// offsets. Anything else (non-pointer, wrong pointee, missing)
    /// refuses — a valid offset with a lying type would mis-chase.
    /// The 8-byte pointer read must sit inside the parent (R4
    /// containment — the BPF target is 64-bit, pointers read u64).
    pub(crate) fn member_ptr_to_struct(
        &self,
        type_name: &str,
        member: &str,
        pointee: &str,
    ) -> Result<u32, BtfError> {
        let (off, mtype) = self.member_typed(type_name, member)?;
        let ptr = self.rec(self.chase_wrappers(mtype)?)?;
        if ptr.kind != KIND_PTR {
            return Err(bad(format!(
                "{type_name}.{member} is kind {}, not a pointer",
                ptr.kind
            )));
        }
        let target = self.rec(self.chase_wrappers(ptr.size_or_type)?)?;
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
        self.check_contained(type_name, off, 8)?;
        Ok(off)
    }

    /// Offset of `member` proven to be an embedded STRUCT/UNION
    /// `name` (wrappers chased): the BPF may add further
    /// member offsets to it directly (no dereference). A pointer,
    /// scalar, or wrong-typed aggregate refuses — adding into a
    /// pointer would read the pointer's bytes as a struct. The
    /// whole embedded extent must sit inside the parent (R4
    /// containment — further offsets add into it).
    pub(crate) fn member_embedded_struct(
        &self,
        type_name: &str,
        member: &str,
        name: &str,
    ) -> Result<u32, BtfError> {
        let (off, mtype) = self.member_typed(type_name, member)?;
        let inner = self.rec(self.chase_wrappers(mtype)?)?;
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
        self.check_contained(type_name, off, inner.size_or_type)?;
        Ok(off)
    }

    /// Offset of `member` proven to be a byte array of at least
    /// `min_len` bytes (ARRAY of 1-byte INT, `nelems` covering the
    /// BPF copy bound): the bounded string copy may fill `min_len`
    /// bytes from it. Shorter arrays refuse — copying past the
    /// member would read the next field as name bytes. The copied
    /// extent must also sit inside the parent (R4 containment).
    pub(crate) fn member_bytes(
        &self,
        type_name: &str,
        member: &str,
        min_len: u32,
    ) -> Result<u32, BtfError> {
        let (off, mtype) = self.member_typed(type_name, member)?;
        let arr = self.rec(self.chase_wrappers(mtype)?)?;
        if arr.kind != KIND_ARRAY {
            return Err(bad(format!(
                "{type_name}.{member} is kind {}, not a byte ARRAY",
                arr.kind
            )));
        }
        let (elem, nelems) = self.array_shape(arr)?;
        let elem_rec = self.rec(self.chase_wrappers(elem)?)?;
        if elem_rec.kind != KIND_INT || elem_rec.size_or_type != 1 {
            return Err(bad(format!(
                "{type_name}.{member} array element is kind {} size {}, not 1-byte INT",
                elem_rec.kind, elem_rec.size_or_type
            )));
        }
        if nelems < min_len {
            return Err(bad(format!(
                "{type_name}.{member} array holds {nelems} bytes, fewer than {min_len}"
            )));
        }
        self.check_contained(type_name, off, min_len)?;
        Ok(off)
    }

    /// Offset of `member` proven to carry the counter value in its
    /// FIRST 4 bytes (R4: the BPF reads exactly one u32 there and
    /// the tracker treats 1 as final-free proof, so the shape must
    /// prove the VALUE, not just the width). Accepted: an INT of
    /// EXACTLY 4 bytes, or a 4-byte STRUCT/UNION with a 4-byte INT
    /// word at byte 0 (the `refcount_t`/`atomic_t` shape — the
    /// whole wrapper IS the one counter word). Refused: wider INTs
    /// (a 64-bit `0x1_0000_0001` reads a lying low word),
    /// multi-word wrappers (a marker before the counter reads the
    /// marker — size ≠ 4 proves nothing about word 0's meaning),
    /// pointers, and narrower shapes. The 4-byte read must also sit
    /// inside the parent (`off + 4 ≤ parent size` — containment,
    /// same as every lifecycle read).
    pub(crate) fn member_counter(&self, type_name: &str, member: &str) -> Result<u32, BtfError> {
        let (off, mtype) = self.member_typed(type_name, member)?;
        let target = self.chase_wrappers(mtype)?;
        let rec = self.rec(target)?;
        let is_counter = match rec.kind {
            KIND_INT => rec.size_or_type == 4,
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
        self.check_contained(type_name, off, 4)?;
        Ok(off)
    }

    /// True when struct/union `id` carries a 4-byte INT word at byte
    /// 0 (R4 counter-leaf proof: some member sits at byte offset 0
    /// with a 4-byte INT leaf — a leading marker or a wider counter
    /// leaves no such word). One nesting level descends (the real
    /// `refcount_t { atomic_t refs; }` → `atomic_t { int counter; }`
    /// chain — each wrapper must itself be exactly 4 bytes, so a
    /// marker beside the nested counter still refuses). Bitfield /
    /// misaligned members at 0 prove nothing (no byte offset to
    /// read) and simply don't qualify.
    fn counter_word_at_zero(&self, id: u32, depth: usize) -> Result<bool, BtfError> {
        if depth > 2 {
            return Ok(false);
        }
        let rec = self.rec(id)?;
        if !matches!(rec.kind, KIND_STRUCT | KIND_UNION) {
            return Ok(false);
        }
        for m in 0..rec.vlen as usize {
            let at = rec.aux_at + m * 12;
            let mtype = read_u32(self.bytes, at + 4, "counter member type")?;
            if mtype == 0 {
                continue;
            }
            let raw = read_u32(self.bytes, at + 8, "counter member offset")?;
            let bits = if rec.kind_flag {
                raw & 0x00ff_ffff
            } else {
                raw
            };
            let bitfield = rec.kind_flag && raw >> 24 != 0;
            if bitfield || !bits.is_multiple_of(8) || bits / 8 != 0 {
                continue;
            }
            let target = self.chase_wrappers(mtype)?;
            let leaf = self.rec(target)?;
            if leaf.kind == KIND_INT && leaf.size_or_type == 4 {
                return Ok(true);
            }
            if matches!(leaf.kind, KIND_STRUCT | KIND_UNION)
                && leaf.size_or_type == 4
                && self.counter_word_at_zero(target, depth + 1)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Containment (R4): the `width`-byte BPF read at root-relative
    /// `off` must sit inside the parent struct/union (a member
    /// offset past the parent's size — corrupt or drifted BTF —
    /// refuses instead of reading the next object as the member).
    fn check_contained(&self, type_name: &str, off: u32, width: u32) -> Result<(), BtfError> {
        let root = self.find_struct(type_name)?;
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
    /// here (callers keep looking outward). Returns the byte offset
    /// AND the leaf member's type id (the shape validators chase the
    /// type; plain offset callers ignore it). Alignment/bitfield checks
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
    ) -> Result<Option<(u32, u32)>, BtfError> {
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
                return Ok(Some((base, mtype)));
            }
            if descend {
                // Anonymous member: descend into struct/union shapes
                // (through const/typedef wrappers), offsets add; the
                // LEAF type id propagates (the shape describes the
                // sought member, not the anonymous carrier).
                if let Some(tid) = self.anon_target(mtype)?
                    && let Some((off, leaf)) = self.member_at(tid, member, depth + 1, path)?
                {
                    return Ok(Some((
                        base.checked_add(off)
                            .ok_or_else(|| bad("anonymous member offset overflows".to_owned()))?,
                        leaf,
                    )));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal hermetic BTF image builder (R4: counter-leaf and
    /// containment regressions without the object-fixture block).
    struct Img {
        types: Vec<u8>,
        strs: Vec<u8>,
        next_id: u32,
    }

    impl Img {
        fn new() -> Self {
            Self {
                types: Vec::new(),
                strs: vec![0],
                next_id: 1,
            }
        }

        fn str(&mut self, s: &str) -> u32 {
            let off = self.strs.len() as u32;
            self.strs.extend_from_slice(s.as_bytes());
            self.strs.push(0);
            off
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
            let name_off = self.str(name);
            // INT aux: 4 bytes encoding (unused here — all zeros).
            self.rec(name_off, KIND_INT, 0, size, &[0, 0, 0, 0])
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
            btf.member_counter("crypto_tfm", "refcnt")
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
            btf.member_counter("crypto_tfm", "refcnt").is_err(),
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
            btf.member_counter("crypto_tfm", "refcnt")
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
            btf.member_counter("crypto_tfm", "refcnt").is_err(),
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
            .member_counter("crypto_tfm", "refcnt")
            .expect_err("escaping read must refuse");
        assert!(
            format!("{err:?}").contains("escapes"),
            "names containment: {err:?}"
        );
    }

    #[test]
    fn r4_pointer_and_embedded_outside_parent_refuse() {
        // member_ptr_to_struct (8-byte read) and
        // member_embedded_struct (full extent) prove containment.
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
            btf.member_ptr_to_struct("crypto_tfm", "__crt_alg", "crypto_alg")
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
            btf.member_ptr_to_struct("crypto_tfm", "__crt_alg", "crypto_alg")
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
            btf.member_embedded_struct("crypto_skcipher", "base", "crypto_tfm")
                .is_err(),
            "embedded extent [8..24) escapes the 16-byte parent"
        );
    }
}
