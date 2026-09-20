// SPDX-License-Identifier: GPL-3.0-or-later
//! Deterministic manual clock for scripted sessions and golden streams.

/// Test clock holding `u64` nanoseconds; time moves only via [`ManualClock::advance`].
///
/// Never reads the wall clock, so scripted backends and golden JSONL streams
/// stay byte-reproducible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManualClock {
    now: u64,
}

impl ManualClock {
    /// Starts the clock at `start` nanoseconds.
    #[must_use]
    pub fn new(start: u64) -> Self {
        Self { now: start }
    }

    /// Returns the current time in nanoseconds.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Advances the clock by `delta` nanoseconds (saturating at `u64::MAX`)
    /// and returns the new time.
    pub fn advance(&mut self, delta: u64) -> u64 {
        self.now = self.now.saturating_add(delta);
        self.now
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_given_value_and_advances_monotonically() {
        // Moved with the clock from testkit (1B-M4): the scripted
        // session's time source pins its start/advance contract here.
        let mut clock = ManualClock::new(1_000_000);
        assert_eq!(clock.now(), 1_000_000);
        assert_eq!(clock.advance(500), 1_000_500);
        assert_eq!(clock.now(), 1_000_500);
        assert_eq!(clock.advance(0), 1_000_500);
        assert!(clock.now() >= 1_000_500);
    }
}
