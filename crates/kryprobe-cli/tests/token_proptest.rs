// SPDX-License-Identifier: GPL-3.0-or-later
//! Roundtrip property: `security.capability` xattr encode/decode (audit #21).

use kryprobe_cli::token::{decode_capability_xattr, encode_capability_xattr};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// decode(encode(caps)) recovers exactly the representable set (caps <
    /// 64, sorted, deduped) with the EFFECTIVE flag set.
    #[test]
    fn xattr_roundtrip(caps in prop::collection::vec(any::<u32>(), 0..70)) {
        let enc = encode_capability_xattr(&caps);
        let (got, effective) =
            decode_capability_xattr(&enc).expect("encode output must decode");
        let mut expected: Vec<u32> =
            caps.into_iter().filter(|c| *c < 64).collect();
        expected.sort();
        expected.dedup();
        prop_assert_eq!(got, expected);
        prop_assert!(effective);
    }

    /// Decoder is total: arbitrary bytes never panic, wrong lengths reject.
    #[test]
    fn xattr_decode_total(bytes in prop::collection::vec(any::<u8>(), 0..32)) {
        let out = decode_capability_xattr(&bytes);
        if bytes.len() != 12 && bytes.len() != 20 {
            prop_assert!(out.is_none());
        }
    }
}
