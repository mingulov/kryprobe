// SPDX-License-Identifier: GPL-3.0-or-later
//! File-capability xattr I/O behind the privilege seam (K5 Task 5).
//!
//! The CLI's `token mint|status` verbs need `security.capability`
//! reads/writes, but ADR-0002 Rule B forbids `libc::setxattr`/
//! `getxattr` call sites outside this crate — so the two syscalls live
//! here and the CLI calls these wrappers. Errors are raw errnos (the
//! [`crate::probe::bpf_sys`] idiom); callers render them.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// The file-capability xattr name.
const XATTR_NAME: &str = "security.capability";

/// Last thread-local errno, `EIO` when unreadable (the `bpf_sys`
/// fallback precedent).
fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// Writes the `security.capability` xattr (create-or-replace). A `NUL`
/// byte in the path fails with `EINVAL` before any syscall.
pub fn set_capability_xattr(target: &Path, value: &[u8]) -> Result<(), i32> {
    let c_path = CString::new(target.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
    let c_name = CString::new(XATTR_NAME).expect("static name has no NUL");
    // SAFETY: pointers borrow live `CString`/slice bytes for the call.
    let ret = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            value.as_ptr().cast::<std::os::raw::c_void>(),
            value.len(),
            0,
        )
    };
    if ret == 0 { Ok(()) } else { Err(last_errno()) }
}

/// Reads one `security.capability` value: size probe, then the read.
/// A `NUL` byte in the path fails with `EINVAL` before any syscall.
pub fn get_capability_xattr(target: &Path) -> Result<Vec<u8>, i32> {
    let c_path = CString::new(target.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
    let c_name = CString::new(XATTR_NAME).expect("static name has no NUL");
    // SAFETY: null value + 0 size probes the length (documented
    // `getxattr` behavior); the second call borrows a live buffer.
    let size = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            std::ptr::null_mut::<std::os::raw::c_void>(),
            0,
        )
    };
    if size < 0 {
        return Err(last_errno());
    }
    let mut buf = vec![0u8; size as usize];
    let got = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            buf.as_mut_ptr().cast::<std::os::raw::c_void>(),
            buf.len(),
        )
    };
    if got < 0 {
        return Err(last_errno());
    }
    buf.truncate(got as usize);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nul_path_fails_before_syscall() {
        let bad = Path::new("has\0nul");
        assert_eq!(set_capability_xattr(bad, &[0u8; 20]), Err(libc::EINVAL));
        assert_eq!(get_capability_xattr(bad), Err(libc::EINVAL));
    }

    #[test]
    fn missing_file_reports_enoent() {
        assert_eq!(
            get_capability_xattr(Path::new("/nonexistent-k5-filecaps-zzz")),
            Err(libc::ENOENT)
        );
    }

    #[test]
    fn file_without_xattr_reports_enodata() {
        let dir = std::env::temp_dir().join(format!("kryprobe-k5-filecaps-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let file = dir.join("plain");
        std::fs::write(&file, b"no xattr here").expect("write fixture");
        assert_eq!(get_capability_xattr(&file), Err(libc::ENODATA));
        std::fs::remove_dir_all(&dir).ok();
    }
}
