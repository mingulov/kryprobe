// SPDX-License-Identifier: GPL-3.0-or-later
//! Totality properties for the 112-byte LEdge record decoder (audit #20):
//! arbitrary bytes never panic, wrong lengths fail closed, decoding is
//! deterministic.

use kryprobe_privilege::kcrypto_lifecycle::decode::{DecodeDrop, decode_record};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn decode_record_total_len_gated_deterministic(
        bytes in prop::collection::vec(any::<u8>(), 0..160),
    ) {
        let first = decode_record(&bytes);
        let second = decode_record(&bytes);
        prop_assert!(first == second);
        if bytes.len() != 112 {
            prop_assert!(matches!(first, Err(DecodeDrop::BadLength)));
        }
    }
}
