// SPDX-License-Identifier: GPL-3.0-or-later
//! RAII scratch-dir guard tests (BP-L3).

use kryprobe_testkit::TempDir;

/// Same tag twice yields two distinct live dirs (pid+tag alone
/// would collide under same-pid parallel tests).
#[test]
fn same_tag_guards_do_not_collide() {
    let a = TempDir::named("collide").expect("scratch a");
    let b = TempDir::named("collide").expect("scratch b");
    assert_ne!(a.path(), b.path());
    assert!(a.path().is_dir());
    assert!(b.path().is_dir());
    assert!(
        a.path()
            .to_string_lossy()
            .contains(&std::process::id().to_string())
    );
}

/// Drop removes the dir even with contents (no `/tmp` accumulation
/// on assertion failure — `Drop` runs during unwinding too).
#[test]
fn drop_removes_dir_with_contents() {
    let path = {
        let guard = TempDir::named("dropme").expect("scratch");
        let path = guard.path().to_path_buf();
        std::fs::write(path.join("f"), b"x").expect("write");
        assert!(path.is_dir());
        path
    };
    assert!(!path.exists(), "guard drop removes {path:?}");
}
