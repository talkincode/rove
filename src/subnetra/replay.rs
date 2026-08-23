//! Subnetra v1 anti-replay window (PROTOCOL.md §6).
//!
//! A 64-entry sliding window over accepted sequence numbers: `highest` plus a
//! 64-bit `bitmap`, where bit *i* means `highest - i` has been seen. The window
//! is reset whenever a strictly newer epoch is adopted (§5.5), which is why
//! [`ReplayWindow`] exposes an explicit [`ReplayWindow::reset`].

/// Width of the sliding window in sequence numbers.
const WINDOW: u64 = 64;

#[derive(Debug, Default, Clone)]
pub struct ReplayWindow {
    /// Highest sequence number accepted so far (`0` = nothing seen yet). Because
    /// the sender's counter starts at `1` (§4), a fresh window's first datagram
    /// always takes the `seq > highest` fast path.
    highest: u64,
    /// Bit *i* set ⇔ `highest - i` was accepted. Bit 0 tracks `highest` itself.
    bitmap: u64,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset to the empty state — called by the session when it adopts a strictly
    /// newer epoch (§5 step 5), so sequence numbers may safely restart at `1`.
    pub fn reset(&mut self) {
        self.highest = 0;
        self.bitmap = 0;
    }

    /// Apply the sliding window to `seq` (§6). Returns `true` if the datagram is
    /// fresh (and records it), `false` if it is a replay or older than the window
    /// (caller drops silently). MUST be called only *after* the datagram has
    /// authenticated (§5 ordering), so a forged `seq` can never poison the window.
    pub fn check_and_set(&mut self, seq: u64) -> bool {
        if seq > self.highest {
            // Advance the window; shift in the gap, then mark the new highest.
            let shift = seq - self.highest;
            if shift >= WINDOW {
                self.bitmap = 0;
            } else {
                self.bitmap <<= shift;
            }
            self.bitmap |= 1; // bit 0 = the new highest
            self.highest = seq;
            true
        } else {
            let diff = self.highest - seq;
            if diff >= WINDOW {
                return false; // too old
            }
            let mask = 1u64 << diff;
            if self.bitmap & mask != 0 {
                false // replay
            } else {
                self.bitmap |= mask;
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_forward_sequence() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(1));
        assert!(w.check_and_set(2));
        assert!(w.check_and_set(3));
    }

    #[test]
    fn rejects_exact_replay() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(5));
        assert!(!w.check_and_set(5));
    }

    #[test]
    fn accepts_in_window_reorder_then_rejects_its_replay() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(5));
        assert!(w.check_and_set(3)); // lower but unseen and in-window
        assert!(!w.check_and_set(3)); // now a replay
    }

    #[test]
    fn rejects_too_old() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(100));
        assert!(!w.check_and_set(100 - WINDOW)); // exactly at the edge is too old
        assert!(!w.check_and_set(1));
        assert!(w.check_and_set(100 - WINDOW + 1)); // just inside the window
    }

    #[test]
    fn large_jump_clears_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(1));
        assert!(w.check_and_set(1000));
        // Old seq now far outside the window.
        assert!(!w.check_and_set(1));
        // But the new highest's neighbourhood still works.
        assert!(w.check_and_set(999));
    }

    #[test]
    fn reset_forgets_history() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(10));
        w.reset();
        // After reset, the same seq is fresh again (new epoch).
        assert!(w.check_and_set(1));
    }
}
