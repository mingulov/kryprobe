// SPDX-License-Identifier: GPL-3.0-or-later
//! Glob matcher: `*` (multi) + `?` (single) only, no character classes
//! (D5). Hand-rolled (no new dep); everything else is literal —
//! brackets, backslashes, and braces never carry meaning.
//!
//! Matching is byte-wise (kernel names are ASCII); `?` matches one
//! byte, never part of a multi-byte sequence unsafely (a literal
//! multi-byte char still matches itself byte for byte).

/// Returns true when `pattern` matches all of `text` (`*` spans any
/// run including empty, `?` spans exactly one byte).
#[must_use]
pub fn matches(pattern: &str, text: &str) -> bool {
    let (pat, txt) = (pattern.as_bytes(), text.as_bytes());
    let (mut px, mut tx) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while tx < txt.len() {
        if px < pat.len() && (pat[px] == b'?' || pat[px] == txt[tx]) {
            px += 1;
            tx += 1;
        } else if px < pat.len() && pat[px] == b'*' {
            star = Some(px);
            px += 1;
            mark = tx;
        } else if let Some(star_at) = star {
            px = star_at + 1;
            mark += 1;
            tx = mark;
        } else {
            return false;
        }
    }
    while px < pat.len() && pat[px] == b'*' {
        px += 1;
    }
    px == pat.len()
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn exact_and_empty() {
        assert!(matches("", ""));
        assert!(!matches("", "x"));
        assert!(!matches("x", ""));
        assert!(matches("md5", "md5"));
        assert!(!matches("md5", "md4"));
        assert!(!matches("md5", "md5x"));
    }

    #[test]
    fn question_spans_one_byte() {
        assert!(matches("m?5", "md5"));
        assert!(!matches("m?5", "m5"));
        assert!(!matches("m?5", "mdd5"));
        assert!(!matches("?", ""));
    }

    #[test]
    fn star_spans_any_run() {
        assert!(matches("*", ""));
        assert!(matches("*", "anything-at-all"));
        assert!(matches("md*", "md5"));
        assert!(matches("md*", "md"));
        assert!(matches("*5", "md5"));
        assert!(matches("*md5*", "xxmd5yy"));
        assert!(!matches("*md5*", "xxmd4yy"));
        assert!(matches("a*b*c", "abc"));
        assert!(matches("a*b*c", "aXXbYYc"));
        assert!(!matches("a*b*c", "aXXbYY"));
        assert!(matches("**", "x"));
    }

    #[test]
    fn only_star_and_question_are_special() {
        // Classes, escapes, and alternates are literal text.
        assert!(!matches("[m]d5", "md5"));
        assert!(matches("[m]d5", "[m]d5"));
        assert!(!matches("md5|sha1", "md5"));
        assert!(!matches("md\\5", "md5"));
        assert!(matches("cbc(aes)", "cbc(aes)"));
        assert!(!matches("cbc(aes)", "cbcaes"));
    }

    #[test]
    fn trailing_star_backtracks() {
        assert!(matches("a*aa", "aaa"));
        assert!(!matches("a*aa", "aab"));
        assert!(matches("*a*b", "aab"));
    }
}
