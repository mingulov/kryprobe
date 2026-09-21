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
//! Only the verbs the Task-2 suite needs are ported (`skcipher`, `aead`,
//! `hash`, `burst`); the K0-only `prealloc`/`hashmulti` shapes stay in C.
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

/// `skcipher` roundtrip: `ops` encrypts + `ops` decrypts of 32B (C
/// `do_skcipher`: key 16B `0x42`, IV 16B `0x11`, pt 32B `0xaa`,
/// `ecb`-prefix algs take a zero IV).
pub fn skcipher_roundtrip(alg: &str, ops: u64) -> Result<CipherCounts, FixtureError> {
    skcipher_roundtrip_with(alg, ops, &[0x42u8; 16], &[0x11u8; 16], &[0xaau8; 32])
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
    let mut dout = [0u8; 32];
    let mut enc = 0u64;
    while enc < ops {
        send_op(&op, ALG_OP_ENCRYPT, &iv, &msg)?;
        read_exact(&op, &mut out, 48, "aead enc read")?;
        enc += 1;
    }
    let mut dec = 0u64;
    while dec < ops {
        send_op(&op, ALG_OP_DECRYPT, &iv, &out)?;
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
/// update→final path (`crypto_shash_finup`) rather than single-shot
/// `crypto_shash_digest`.
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
