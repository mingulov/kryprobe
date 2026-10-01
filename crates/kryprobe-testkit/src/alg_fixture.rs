// SPDX-License-Identifier: GPL-3.0-or-later
//! Committed AF_ALG traffic fixture (K1 Task 2): exact-count crypto ops.
//!
//! Rust port of the K0 spike `.artifacts/k0/alg_fixture.c` (same socket
//! choreography, same key/IV/plaintext bytes, same ground-truth counts)
//! with no C toolchain: unprivileged `libc` syscalls only. Every entry
//! returns the counts it actually performed, so privileged exactness
//! tests compare sensor deltas against fixture-reported truth (P4
//! method), never against requested inputs.
//!
//! The `hash_digest_multi` helper also preserves C `hashmulti` parity.
//! `PreparedHashFinups` is a separate, digest-checked finalization control;
//! it deliberately prepares input before a sensor's measured window.
//! Added: `aead_decrypt_bad_tag` (EBADMSG proof for the errors bucket).

use std::io;

/// `AF_ALG` cmsg types (UAPI `linux/if_alg.h`).
const ALG_SET_KEY: i32 = 1;
const ALG_SET_IV: i32 = 2;
const ALG_SET_OP: i32 = 3;
const ALG_SET_AEAD_AUTHSIZE: i32 = 5;
/// `AF_ALG` cipher ops (UAPI `linux/if_alg.h`).
const ALG_OP_DECRYPT: u32 = 0;
const ALG_OP_ENCRYPT: u32 = 1;

/// `CMSG_ALIGN` (libc exposes no such fn; Linux aligns control lengths
/// to `sizeof(size_t)` = 8 — `socket.h`).
fn cmsg_align(len: usize) -> usize {
    len.next_multiple_of(8)
}

/// Fixture failure: syscall errno or a short-read protocol check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureError {
    /// Syscall failed: stage + errno (mirrors the C `FAIL <stage>` lines).
    Syscall {
        /// Fixture stage that failed.
        stage: &'static str,
        /// Kernel errno.
        errno: i32,
    },
    /// A read returned an unexpected length (counts would lie, so fail).
    ShortRead {
        /// Fixture stage that short-read.
        stage: &'static str,
        /// Bytes expected.
        want: usize,
        /// Bytes (or error) returned.
        got: isize,
    },
    /// An op that must fail succeeded (bad-tag decrypt accepted: the
    /// errors-bucket proof is void, so fail instead of misattributing).
    UnexpectedOk {
        /// Fixture stage that unexpectedly succeeded.
        stage: &'static str,
        /// Bytes returned.
        got: isize,
    },
    /// The prepared-finup control supports only its two fixed goldens.
    UnsupportedFinupAlgorithm,
    /// A synthetic digest disagreed with the independent fixed golden.
    DigestMismatch,
}

impl std::fmt::Display for FixtureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Syscall { stage, errno } => {
                write!(f, "AF_ALG fixture {stage}: errno {errno}")
            }
            Self::ShortRead { stage, want, got } => {
                write!(f, "AF_ALG fixture {stage}: want {want} bytes, got {got}")
            }
            Self::UnexpectedOk { stage, got } => {
                write!(f, "AF_ALG fixture {stage}: expected failure, got {got}")
            }
            Self::UnsupportedFinupAlgorithm => write!(f, "prepared finup needs sha256 or sha512"),
            Self::DigestMismatch => write!(f, "prepared finup digest disagrees with golden"),
        }
    }
}

impl std::error::Error for FixtureError {}

/// RAII `AF_ALG` socket: closes on all paths.
struct AlgFd(i32);

impl AlgFd {
    fn new(fd: i32) -> Self {
        Self(fd)
    }
}

impl Drop for AlgFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: owned fd, closed once.
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

fn last_errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// `struct sockaddr_alg` bytes (UAPI: family u16 + type[14] + feat/mask
/// u32 + name[64] = 88 bytes), `strncpy`-style padded like the C.
fn sockaddr_alg(salg_type: &str, name: &str) -> [u8; 88] {
    let mut out = [0u8; 88];
    out[0..2].copy_from_slice(&(libc::AF_ALG as u16).to_ne_bytes());
    let type_bytes = salg_type.as_bytes();
    let type_len = type_bytes.len().min(13);
    out[2..2 + type_len].copy_from_slice(&type_bytes[..type_len]);
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(63);
    out[24..24 + name_len].copy_from_slice(&name_bytes[..name_len]);
    out
}

/// `socket(AF_ALG, SOCK_SEQPACKET)` + `bind` to `type(name)` (C `alg_bind`).
fn alg_bind(salg_type: &str, name: &str) -> Result<AlgFd, FixtureError> {
    // SAFETY: plain socket creation; no pointers.
    let fd = unsafe { libc::socket(libc::AF_ALG, libc::SOCK_SEQPACKET, 0) };
    if fd < 0 {
        return Err(FixtureError::Syscall {
            stage: "socket",
            errno: last_errno(),
        });
    }
    let addr = sockaddr_alg(salg_type, name);
    // SAFETY: `addr` is a live 88-byte `sockaddr_alg`.
    let bound = unsafe {
        libc::bind(
            fd,
            addr.as_ptr().cast::<libc::sockaddr>(),
            addr.len() as libc::socklen_t,
        )
    };
    if bound != 0 {
        let errno = last_errno();
        // SAFETY: freshly created fd, closed once here.
        unsafe {
            libc::close(fd);
        }
        return Err(FixtureError::Syscall {
            stage: "bind",
            errno,
        });
    }
    Ok(AlgFd::new(fd))
}

/// `setsockopt(ALG_SET_KEY)` with the C's zero-length fallback (some
/// templates refuse a 16-byte key; a 0-length key means "no key").
fn set_key(tfm: &AlgFd, key: &[u8]) -> Result<(), FixtureError> {
    // SAFETY: `key` outlives the call.
    let first = unsafe {
        libc::setsockopt(
            tfm.0,
            libc::SOL_ALG,
            ALG_SET_KEY,
            key.as_ptr().cast::<libc::c_void>(),
            key.len() as libc::socklen_t,
        )
    };
    if first == 0 {
        return Ok(());
    }
    // SAFETY: zero length (the C passes `key, 0`).
    let retry = unsafe {
        libc::setsockopt(
            tfm.0,
            libc::SOL_ALG,
            ALG_SET_KEY,
            key.as_ptr().cast::<libc::c_void>(),
            0,
        )
    };
    if retry == 0 {
        return Ok(());
    }
    Err(FixtureError::Syscall {
        stage: "setkey",
        errno: last_errno(),
    })
}

/// One cipher op: `sendmsg` with `ALG_SET_OP` + `ALG_SET_IV` cmsgs (C
/// `send_op`; the C's assoclen variant is unused — AEAD passes none).
fn send_op(opfd: &AlgFd, op: u32, iv: &[u8], input: &[u8]) -> Result<(), FixtureError> {
    // Cmsg buffer: OP (u32) + IV (`af_alg_iv` + up to 64B), same sizing.
    let mut cbuf = [0u8; 256];
    let iov = libc::iovec {
        iov_base: input.as_ptr() as *mut libc::c_void,
        iov_len: input.len(),
    };
    let mut msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &iov as *const libc::iovec as *mut libc::iovec,
        msg_iovlen: 1,
        msg_control: cbuf.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: cbuf.len(),
        msg_flags: 0,
    };
    // SAFETY: `cbuf`/`iov` outlive the `sendmsg`; cmsg writes stay in
    // bounds (OP header + u32, then IV header + ivlen word + iv bytes;
    // callers cap iv at 16B, buffer is 256B).
    unsafe {
        let first = libc::CMSG_FIRSTHDR(&msg);
        if first.is_null() {
            return Err(FixtureError::Syscall {
                stage: "sendmsg/cmsg",
                errno: libc::ENOBUFS,
            });
        }
        (*first).cmsg_level = libc::SOL_ALG;
        (*first).cmsg_type = ALG_SET_OP;
        (*first).cmsg_len = libc::CMSG_LEN(4) as usize;
        (libc::CMSG_DATA(first) as *mut u32).write_unaligned(op);
        let second = libc::CMSG_NXTHDR(&msg, first);
        if second.is_null() {
            return Err(FixtureError::Syscall {
                stage: "sendmsg/cmsg",
                errno: libc::ENOBUFS,
            });
        }
        (*second).cmsg_level = libc::SOL_ALG;
        (*second).cmsg_type = ALG_SET_IV;
        (*second).cmsg_len = libc::CMSG_LEN(4 + iv.len() as u32) as usize;
        let iv_data = libc::CMSG_DATA(second);
        (iv_data as *mut u32).write_unaligned(iv.len() as u32);
        std::ptr::copy_nonoverlapping(iv.as_ptr(), iv_data.add(4), iv.len());
        msg.msg_controllen = (second as *const u8).add(cmsg_align((*second).cmsg_len)) as usize
            - cbuf.as_ptr() as usize;
        let sent = libc::sendmsg(opfd.0, &msg, 0);
        if sent < 0 {
            return Err(FixtureError::Syscall {
                stage: "sendmsg",
                errno: last_errno(),
            });
        }
    }
    Ok(())
}

/// `accept(tfm)` (one op socket per fixture call, like the C).
fn op_socket(tfm: &AlgFd) -> Result<AlgFd, FixtureError> {
    // SAFETY: no address capture.
    let op = unsafe { libc::accept(tfm.0, std::ptr::null_mut(), std::ptr::null_mut()) };
    if op < 0 {
        return Err(FixtureError::Syscall {
            stage: "accept",
            errno: last_errno(),
        });
    }
    Ok(AlgFd::new(op))
}

/// One `read` demanding exactly `want` bytes (seqpacket: one per op).
fn read_exact(
    opfd: &AlgFd,
    buf: &mut [u8],
    want: usize,
    stage: &'static str,
) -> Result<(), FixtureError> {
    // SAFETY: `buf` outlives the call.
    let got = unsafe { libc::read(opfd.0, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if got != want as isize {
        return Err(FixtureError::ShortRead { stage, want, got });
    }
    Ok(())
}

/// Encrypt/decrypt counts actually performed (fixture-reported truth).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherCounts {
    /// Encrypt ops completed.
    pub enc: u64,
    /// Decrypt ops completed.
    pub dec: u64,
}

/// Hash counts actually performed (fixture-reported truth).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashCounts {
    /// Digest ops completed.
    pub digests: u64,
    /// Digest length of the last op.
    pub digest_len: usize,
}

/// Burst counts actually performed (fixture-reported truth).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BurstCounts {
    /// Encrypt ops completed in the window.
    pub ops: u64,
    /// Requested window in seconds.
    pub secs: u64,
}

/// Canary key (K1 Task 3): 16B AES key carrying the `KPROBE-CANARY`
/// marker, so the privileged `canary_kcrypto` suite can byte-scan every
/// map + ring dump for leaked key bytes (kp2 §9 never-list tripwire).
pub const CANARY_KEY: &[u8; 16] = b"KPROBE-CANARY-K!";
/// Canary IV (K1 Task 3): same tripwire for the IV bytes (the brief
/// mandates key + plaintext; the IV rides the same marker free).
pub const CANARY_IV: &[u8; 16] = b"KPROBE-CANARY-IV";
/// Canary plaintext (K1 Task 3): 32B input carrying the marker.
pub const CANARY_PT: &[u8; 32] = b"KPROBE-CANARY-PT-BUFFER-01234567";
/// Canary AEAD tag (R2-04): 16B tag carrying the marker — a
/// decrypt leg fed this tag must fail `EBADMSG` (proving the
/// marked tag traversed the kernel decrypt path) while the
/// sensor captures none of its bytes.
pub const CANARY_TAG: &[u8; 16] = b"KPROBE-CANARY-TG";

/// `skcipher` roundtrip: `ops` encrypts + `ops` decrypts of 32B (C
/// `do_skcipher`: key 16B `0x42`, IV 16B `0x11`, pt 32B `0xaa`,
/// `ecb`-prefix algs take a zero IV).
pub fn skcipher_roundtrip(alg: &str, ops: u64) -> Result<CipherCounts, FixtureError> {
    skcipher_roundtrip_with(alg, ops, &[0x42u8; 16], &[0x11u8; 16], &[0xaau8; 32])
}

/// One 32B encrypt on an already-bound skcipher fd (T07-04/F05: the
/// caller binds + keys the socket, the SENSOR attaches, then this op
/// runs — the sensor's first observation of the transform is the
/// submit edge, so the generation is op-first-seen. Caller keeps
/// ownership of `bound_fd`; the op socket closes on return. Fixed
/// bytes (IV 16B `0x11`, pt 32B `0xaa` — CBC-shaped algs; `ecb`
/// callers must pass their own IV story, so this helper refuses
/// nothing and documents CBC-only).
pub fn skcipher_encrypt_once(bound_fd: std::os::fd::RawFd) -> Result<(), FixtureError> {
    skcipher_encrypt_once_with(bound_fd, &[0x11u8; 16], &[0xaau8; 32]).map(|_| ())
}

/// One 32B encrypt on a bound fd with caller buffers (R2-04: the
/// privacy lane passes canary IV/plaintext; returns the 32B
/// ciphertext for a decrypt-back leg).
pub fn skcipher_encrypt_once_with(
    bound_fd: std::os::fd::RawFd,
    iv: &[u8],
    pt: &[u8; 32],
) -> Result<[u8; 32], FixtureError> {
    // SAFETY: no address capture; `bound_fd` stays caller-owned.
    let op = unsafe { libc::accept(bound_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
    if op < 0 {
        return Err(FixtureError::Syscall {
            stage: "accept",
            errno: last_errno(),
        });
    }
    let op = AlgFd::new(op);
    let mut out = [0u8; 32];
    send_op(&op, ALG_OP_ENCRYPT, iv, pt)?;
    read_exact(&op, &mut out, 32, "enc read")?;
    Ok(out)
}

/// One 32B decrypt on a bound fd with caller buffers (R2-04: the
/// privacy lane decrypts back with the canary IV; returns the 32B
/// plaintext so the caller proves the roundtrip).
pub fn skcipher_decrypt_once_with(
    bound_fd: std::os::fd::RawFd,
    iv: &[u8],
    ct: &[u8; 32],
) -> Result<[u8; 32], FixtureError> {
    // SAFETY: no address capture; `bound_fd` stays caller-owned.
    let op = unsafe { libc::accept(bound_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
    if op < 0 {
        return Err(FixtureError::Syscall {
            stage: "accept",
            errno: last_errno(),
        });
    }
    let op = AlgFd::new(op);
    let mut out = [0u8; 32];
    send_op(&op, ALG_OP_DECRYPT, iv, ct)?;
    read_exact(&op, &mut out, 32, "dec read")?;
    Ok(out)
}

/// Canary `skcipher` roundtrip (K1 Task 3): same choreography as
/// [`skcipher_roundtrip`], but key, IV, and plaintext are the
/// `KPROBE-CANARY-*` markers above.
pub fn skcipher_canary_roundtrip(alg: &str, ops: u64) -> Result<CipherCounts, FixtureError> {
    skcipher_roundtrip_with(alg, ops, CANARY_KEY, CANARY_IV, CANARY_PT)
}

/// [`skcipher_roundtrip`] over caller-supplied buffers (the exactness
/// suite keeps the C's fixed bytes; the canary suite passes markers).
fn skcipher_roundtrip_with(
    alg: &str,
    ops: u64,
    key: &[u8; 16],
    iv_full: &[u8; 16],
    pt: &[u8; 32],
) -> Result<CipherCounts, FixtureError> {
    let tfm = alg_bind("skcipher", alg)?;
    let iv: &[u8] = if alg.starts_with("ecb") { &[] } else { iv_full };
    set_key(&tfm, key)?;
    let op = op_socket(&tfm)?;
    let mut out = [0u8; 32];
    let mut enc = 0u64;
    while enc < ops {
        send_op(&op, ALG_OP_ENCRYPT, iv, pt)?;
        read_exact(&op, &mut out, 32, "enc read")?;
        enc += 1;
    }
    let mut dec = 0u64;
    while dec < ops {
        send_op(&op, ALG_OP_DECRYPT, iv, &out)?;
        read_exact(&op, &mut out, 32, "dec read")?;
        dec += 1;
    }
    Ok(CipherCounts { enc, dec })
}

/// `aead` roundtrip: `ops` encrypts + `ops` decrypts of 32B + 16B tag (C
/// `do_aead`: the authsize quirk rides `optlen`, `optval` ignored).
pub fn aead_roundtrip(alg: &str, ops: u64) -> Result<CipherCounts, FixtureError> {
    aead_roundtrip_with(alg, ops, &[0x42u8; 16], &[0x11u8; 12], &[0xaau8; 32])
}

/// Probe-only `AF_ALG` bind: true when `aead`/`alg` binds on this
/// kernel (no traffic, fd closed). AEAD-dependent tests gate on this:
/// a bind failure means the kernel cannot supply AEAD traffic at all
/// (environmental, not a product defect). Note hosted CI ships
/// `gcm(aes)` but blocks the `algif_aead` autoload — the sudo CI job
/// enables it with `modprobe --ignore-install algif_aead`, so the
/// gate never triggers there; it covers genuinely AEAD-less kernels.
#[must_use]
pub fn aead_alg_available(alg: &str) -> bool {
    alg_bind("aead", alg).is_ok()
}

/// Canary `aead` roundtrip (R2-04): same choreography as
/// [`aead_roundtrip`], but key, IV, and plaintext carry the
/// `KPROBE-CANARY-*` markers (IV is the 12B marker prefix —
/// gcm-shaped algs take a 12B IV).
pub fn aead_canary_roundtrip(alg: &str, ops: u64) -> Result<CipherCounts, FixtureError> {
    let mut iv12 = [0u8; 12];
    iv12.copy_from_slice(&CANARY_IV[..12]);
    aead_roundtrip_with(alg, ops, CANARY_KEY, &iv12, CANARY_PT)
}

/// [`aead_roundtrip`] over caller-supplied buffers (the canary
/// lane passes markers; the tag stays kernel-computed).
pub fn aead_roundtrip_with(
    alg: &str,
    ops: u64,
    key: &[u8; 16],
    iv: &[u8],
    msg: &[u8; 32],
) -> Result<CipherCounts, FixtureError> {
    let tfm = alg_bind("aead", alg)?;
    set_key(&tfm, key)?;
    // SAFETY: null value, `optlen` carries the authsize (kernel quirk).
    let auth = unsafe {
        libc::setsockopt(
            tfm.0,
            libc::SOL_ALG,
            ALG_SET_AEAD_AUTHSIZE,
            std::ptr::null(),
            16,
        )
    };
    if auth != 0 {
        return Err(FixtureError::Syscall {
            stage: "authsize",
            errno: last_errno(),
        });
    }
    let op = op_socket(&tfm)?;
    let mut out = [0u8; 48];
    let mut dout = [0u8; 32];
    let mut enc = 0u64;
    while enc < ops {
        send_op(&op, ALG_OP_ENCRYPT, iv, msg)?;
        read_exact(&op, &mut out, 48, "aead enc read")?;
        enc += 1;
    }
    let mut dec = 0u64;
    while dec < ops {
        send_op(&op, ALG_OP_DECRYPT, iv, &out)?;
        read_exact(&op, &mut dout, 32, "aead dec read")?;
        dec += 1;
    }
    Ok(CipherCounts { enc, dec })
}

/// `aead` bad-tag decrypt: one encrypt, then one decrypt with a
/// corrupted tag. `Ok(())` iff the decrypt leg fails `EBADMSG` (the
/// kernel error path the sensor's errors bucket classifies); any other
/// outcome (wrong errno, accepted tag) is [`FixtureError`].
pub fn aead_decrypt_bad_tag(alg: &str) -> Result<(), FixtureError> {
    let tfm = alg_bind("aead", alg)?;
    let key = [0x42u8; 16];
    let iv = [0x11u8; 12];
    let msg = [0xaau8; 32];
    set_key(&tfm, &key)?;
    // SAFETY: null value, `optlen` carries the authsize (kernel quirk).
    let auth = unsafe {
        libc::setsockopt(
            tfm.0,
            libc::SOL_ALG,
            ALG_SET_AEAD_AUTHSIZE,
            std::ptr::null(),
            16,
        )
    };
    if auth != 0 {
        return Err(FixtureError::Syscall {
            stage: "authsize",
            errno: last_errno(),
        });
    }
    let op = op_socket(&tfm)?;
    let mut out = [0u8; 48];
    send_op(&op, ALG_OP_ENCRYPT, &iv, &msg)?;
    read_exact(&op, &mut out, 48, "bad tag enc read")?;
    // Corrupt the tag (last byte): the decrypt leg must fail EBADMSG.
    out[47] ^= 0xff;
    send_op(&op, ALG_OP_DECRYPT, &iv, &out)?;
    let mut dout = [0u8; 32];
    // SAFETY: `dout` outlives the call.
    let got = unsafe { libc::read(op.0, dout.as_mut_ptr().cast::<libc::c_void>(), dout.len()) };
    if got < 0 {
        let errno = last_errno();
        if errno == libc::EBADMSG {
            return Ok(());
        }
        return Err(FixtureError::Syscall {
            stage: "bad tag decrypt",
            errno,
        });
    }
    Err(FixtureError::UnexpectedOk {
        stage: "bad tag decrypt",
        got,
    })
}

/// `aead` marker-tag decrypt (R2-04): one encrypt with canary
/// key/IV/plaintext, then one decrypt whose 16B tag is
/// [`CANARY_TAG`]. `Ok(())` iff the decrypt leg fails `EBADMSG`
/// (the marked tag traversed the kernel decrypt path — the
/// positive control that tag bytes were live traffic while the
/// sensor captured none of them); any other outcome is
/// [`FixtureError`].
pub fn aead_decrypt_marker_tag(alg: &str) -> Result<(), FixtureError> {
    let tfm = alg_bind("aead", alg)?;
    let mut iv12 = [0u8; 12];
    iv12.copy_from_slice(&CANARY_IV[..12]);
    set_key(&tfm, CANARY_KEY)?;
    // SAFETY: null value, `optlen` carries the authsize (kernel quirk).
    let auth = unsafe {
        libc::setsockopt(
            tfm.0,
            libc::SOL_ALG,
            ALG_SET_AEAD_AUTHSIZE,
            std::ptr::null(),
            16,
        )
    };
    if auth != 0 {
        return Err(FixtureError::Syscall {
            stage: "authsize",
            errno: last_errno(),
        });
    }
    let op = op_socket(&tfm)?;
    let mut out = [0u8; 48];
    send_op(&op, ALG_OP_ENCRYPT, &iv12, CANARY_PT)?;
    read_exact(&op, &mut out, 48, "marker tag enc read")?;
    // Swap the kernel tag for the canary tag: the decrypt leg
    // must fail EBADMSG.
    out[32..48].copy_from_slice(CANARY_TAG);
    send_op(&op, ALG_OP_DECRYPT, &iv12, &out)?;
    let mut dout = [0u8; 32];
    // SAFETY: `dout` outlives the call.
    let got = unsafe { libc::read(op.0, dout.as_mut_ptr().cast::<libc::c_void>(), dout.len()) };
    if got < 0 {
        let errno = last_errno();
        if errno == libc::EBADMSG {
            return Ok(());
        }
        return Err(FixtureError::Syscall {
            stage: "marker tag decrypt",
            errno,
        });
    }
    Err(FixtureError::UnexpectedOk {
        stage: "marker tag decrypt",
        got,
    })
}

/// `hash` digests: `ops` single-shot digests of 64B (C `do_hash`).
pub fn hash_digest(alg: &str, ops: u64) -> Result<HashCounts, FixtureError> {
    let tfm = alg_bind("hash", alg)?;
    let op = op_socket(&tfm)?;
    let data = [0xaau8; 64];
    let mut out = [0u8; 128];
    let mut digests = 0u64;
    let mut digest_len = 0usize;
    while digests < ops {
        // SAFETY: `data`/`out` outlive the calls.
        let sent = unsafe { libc::send(op.0, data.as_ptr().cast::<libc::c_void>(), data.len(), 0) };
        if sent != data.len() as isize {
            return Err(FixtureError::Syscall {
                stage: "hash send",
                errno: last_errno(),
            });
        }
        let got = unsafe { libc::read(op.0, out.as_mut_ptr().cast::<libc::c_void>(), out.len()) };
        if got <= 0 {
            return Err(FixtureError::ShortRead {
                stage: "hash read",
                want: 1,
                got,
            });
        }
        digest_len = got as usize;
        digests += 1;
    }
    Ok(HashCounts {
        digests,
        digest_len,
    })
}

/// Multi-part `hash` digests: `ops` digests, each fed as 32B
/// (`MSG_MORE`) + empty final chunk (C `do_hashmulti`). Exercises the
/// update→final path rather than single-shot `crypto_shash_digest`.
/// This does not imply a finup observation: the qualified 6.12 route
/// uses separate, unhooked update/final APIs. See `PreparedHashFinups`
/// for an explicit in-window finup control on the qualified shash routes.
pub fn hash_digest_multi(alg: &str, ops: u64) -> Result<HashCounts, FixtureError> {
    let tfm = alg_bind("hash", alg)?;
    let op = op_socket(&tfm)?;
    let data = [0xaau8; 32];
    let mut out = [0u8; 128];
    let mut digests = 0u64;
    let mut digest_len = 0usize;
    while digests < ops {
        // SAFETY: `data`/`out` outlive the calls.
        let sent = unsafe {
            libc::send(
                op.0,
                data.as_ptr().cast::<libc::c_void>(),
                data.len(),
                libc::MSG_MORE,
            )
        };
        if sent != data.len() as isize {
            return Err(FixtureError::Syscall {
                stage: "hashmulti send1",
                errno: last_errno(),
            });
        }
        let sent = unsafe { libc::send(op.0, data.as_ptr().cast::<libc::c_void>(), 0, 0) };
        if sent != 0 {
            return Err(FixtureError::Syscall {
                stage: "hashmulti send2",
                errno: last_errno(),
            });
        }
        let got = unsafe { libc::read(op.0, out.as_mut_ptr().cast::<libc::c_void>(), out.len()) };
        if got <= 0 {
            return Err(FixtureError::ShortRead {
                stage: "hashmulti read",
                want: 1,
                got,
            });
        }
        digest_len = got as usize;
        digests += 1;
    }
    Ok(HashCounts {
        digests,
        digest_len,
    })
}

/// An unfinished operation retained across the measurement window.
/// Prepare before attaching the sensor, then call [`Self::finish`].
/// Each cloned operation finalizes 16 bytes; the full message is 48 bytes.
/// Exact shash-finup expectations apply only to independently qualified
/// shash-backed SHA-256/SHA-512 routes, not arbitrary ahash providers.
pub struct PreparedHashFinups {
    parent: AlgFd,
    expected: &'static [u8],
}

impl std::fmt::Debug for PreparedHashFinups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedHashFinups").finish_non_exhaustive()
    }
}

impl PreparedHashFinups {
    /// Feed 32 synthetic AA bytes with MSG_MORE before measurement.
    /// Goldens are SHA-256/SHA-512 of AA*32 || BB*16, independently
    /// computed with Python hashlib; they are never sensor-derived.
    pub fn new(alg: &str) -> Result<Self, FixtureError> {
        let expected: &'static [u8] = match alg {
            "sha256" => &[
                0x0f, 0x96, 0x3b, 0xa3, 0x6a, 0x53, 0x2c, 0xb4, 0x20, 0x73, 0xce, 0x5b, 0xb4, 0xb9,
                0x46, 0xb9, 0x11, 0x09, 0xed, 0x40, 0x9e, 0x02, 0x92, 0x05, 0x67, 0xfc, 0x11, 0x92,
                0xa7, 0x73, 0xa9, 0x28,
            ],
            "sha512" => &[
                0x3b, 0x8f, 0xb0, 0xcf, 0xb8, 0x24, 0xa5, 0xc2, 0x79, 0xb7, 0x4e, 0x3f, 0x68, 0xba,
                0xe1, 0x82, 0x73, 0x2d, 0x4d, 0x4a, 0xa2, 0x75, 0x7e, 0xe0, 0xe2, 0x37, 0xc8, 0xf4,
                0x04, 0xac, 0xd8, 0x78, 0x9f, 0xdb, 0xd8, 0xcf, 0xe5, 0x04, 0x20, 0x83, 0x75, 0x2a,
                0xe3, 0x02, 0x91, 0x77, 0xfe, 0xd6, 0x75, 0x4f, 0x80, 0xda, 0x95, 0x8c, 0xa8, 0xa4,
                0x26, 0xe9, 0x5f, 0x70, 0xee, 0x32, 0x90, 0xc7,
            ],
            _ => return Err(FixtureError::UnsupportedFinupAlgorithm),
        };
        let tfm = alg_bind("hash", alg)?;
        let parent = op_socket(&tfm)?;
        let prefix = [0xaau8; 32];
        // SAFETY: prefix outlives the call; parent is an owned operation fd.
        let sent = unsafe {
            libc::send(
                parent.0,
                prefix.as_ptr().cast(),
                prefix.len(),
                libc::MSG_MORE,
            )
        };
        if sent != prefix.len() as isize {
            return Err(FixtureError::ShortRead {
                stage: "finup prefix send",
                want: prefix.len(),
                got: sent,
            });
        }
        Ok(Self { parent, expected })
    }

    /// Accept on the unfinished operation (not the transform binding),
    /// then finalize each clone. The parent stays unchanged and open.
    /// Only completed, length-checked, golden-matching digests count.
    pub fn finish(&self, ops: u64) -> Result<HashCounts, FixtureError> {
        // A final chunk cannot straddle a Linux page and become two updates.
        #[repr(align(64))]
        struct FinalChunk([u8; 16]);
        let tail = FinalChunk([0xbb; 16]);
        let mut out = [0u8; 128];
        let mut digests = 0;
        while digests < ops {
            let clone = op_socket(&self.parent)?;
            // SAFETY: tail and out outlive the calls; clone is owned.
            let sent = unsafe { libc::send(clone.0, tail.0.as_ptr().cast(), tail.0.len(), 0) };
            if sent != tail.0.len() as isize {
                return Err(FixtureError::ShortRead {
                    stage: "finup final send",
                    want: tail.0.len(),
                    got: sent,
                });
            }
            read_exact(&clone, &mut out, self.expected.len(), "finup digest read")?;
            if &out[..self.expected.len()] != self.expected {
                return Err(FixtureError::DigestMismatch);
            }
            digests += 1;
        }
        Ok(HashCounts {
            digests,
            digest_len: if digests == 0 { 0 } else { self.expected.len() },
        })
    }
}

/// `burst`: 4KB encrypts in a `secs`-whole-seconds window (C `do_burst`:
/// same `tv_sec`-difference window, same buffers).
pub fn burst_encrypt(alg: &str, secs: u64) -> Result<BurstCounts, FixtureError> {
    let tfm = alg_bind("skcipher", alg)?;
    let key = [0x42u8; 16];
    let iv_full = [0x11u8; 16];
    let iv: &[u8] = if alg.starts_with("ecb") {
        &[]
    } else {
        &iv_full
    };
    let pt = [0xaau8; 4096];
    // The C `do_burst` has no zero-length fallback (plain `die`).
    // SAFETY: `key` outlives the call.
    let keyed = unsafe {
        libc::setsockopt(
            tfm.0,
            libc::SOL_ALG,
            ALG_SET_KEY,
            key.as_ptr().cast::<libc::c_void>(),
            key.len() as libc::socklen_t,
        )
    };
    if keyed != 0 {
        return Err(FixtureError::Syscall {
            stage: "setkey",
            errno: last_errno(),
        });
    }
    let op = op_socket(&tfm)?;
    let mut out = [0u8; 4096];
    // SAFETY: `timespec` outlives the call.
    let mut start = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut start) } != 0 {
        return Err(FixtureError::Syscall {
            stage: "clock_gettime",
            errno: last_errno(),
        });
    }
    let mut ops = 0u64;
    loop {
        send_op(&op, ALG_OP_ENCRYPT, iv, &pt)?;
        read_exact(&op, &mut out, 4096, "burst read")?;
        ops += 1;
        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `timespec` outlives the call.
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
            return Err(FixtureError::Syscall {
                stage: "clock_gettime",
                errno: last_errno(),
            });
        }
        if now.tv_sec - start.tv_sec >= secs as libc::time_t {
            break;
        }
    }
    Ok(BurstCounts { ops, secs })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bogus algorithms never probe available (environment-independent).
    #[test]
    fn bogus_aead_alg_is_unavailable() {
        assert!(!aead_alg_available("definitely-not-an-alg-xyz"));
    }

    /// Availability is deterministic within a boot (bind, close, repeat).
    #[test]
    fn availability_is_deterministic() {
        assert_eq!(
            aead_alg_available("gcm(aes)"),
            aead_alg_available("gcm(aes)")
        );
    }
}
