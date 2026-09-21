// SPDX-License-Identifier: GPL-3.0-or-later
//! Workspace-root climbing (BP-L6): one anchored walk-up shared by
//! the seam gate, the manifest gate, the BPF lanes, and the
//! toolchain-pin reader (previously four copies with three anchors).

use std::path::PathBuf;

/// Climb from `start` to the first ancestor (inclusive) holding
/// `marker` (file or dir — [`Path::exists`] covers both anchor
/// shapes the old copies used). `None` past the filesystem root.
pub(crate) fn climb_to_from(mut dir: PathBuf, marker: &str) -> Option<PathBuf> {
    loop {
        if dir.join(marker).exists() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// [`climb_to_from`] from the process working directory.
pub(crate) fn climb_to(marker: &str) -> Option<PathBuf> {
    climb_to_from(std::env::current_dir().ok()?, marker)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn climbs_to_nearest_marker() {
        let scratch = kryprobe_testkit::TempDir::named("root-climb").expect("scratch dir");
        let nest = scratch.path().join("a").join("b");
        std::fs::create_dir_all(&nest).expect("nest");
        std::fs::write(scratch.path().join("marker-x1"), b"x").expect("marker");
        assert_eq!(
            climb_to_from(nest.clone(), "marker-x1").as_deref(),
            Some(scratch.path())
        );
        assert_eq!(
            climb_to_from(nest, "marker-x1-absent-9f2"),
            None,
            "unique marker matches nowhere up the tree"
        );
    }
}
