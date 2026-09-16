//! Sliding window replay protection (RFC 6479 style, 64 entries).

/// Anti-replay window over a monotonically increasing counter.
#[derive(Clone, Debug, Default)]
pub struct ReplayWindow {
    /// Highest counter accepted so far (+1 once anything was accepted).
    top: u64,
    bitmap: u64,
    accepted_any: bool,
}

impl ReplayWindow {
    pub const SIZE: u64 = 64;

    pub fn new() -> Self {
        Self::default()
    }

    /// Check a counter without recording it.
    pub fn check(&self, ctr: u64) -> bool {
        if !self.accepted_any {
            return true;
        }
        if ctr > self.top {
            return true;
        }
        let diff = self.top - ctr;
        if diff >= Self::SIZE {
            return false;
        }
        self.bitmap & (1u64 << diff) == 0
    }

    /// Check and record. Returns false if replayed / too old.
    pub fn accept(&mut self, ctr: u64) -> bool {
        if !self.check(ctr) {
            return false;
        }
        if !self.accepted_any {
            self.accepted_any = true;
            self.top = ctr;
            self.bitmap = 1;
            return true;
        }
        if ctr > self.top {
            let shift = ctr - self.top;
            self.bitmap = if shift >= Self::SIZE { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.top = ctr;
        } else {
            self.bitmap |= 1u64 << (self.top - ctr);
        }
        true
    }

    pub fn highest(&self) -> Option<u64> {
        if self.accepted_any {
            Some(self.top)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_replays_and_accepts_out_of_order() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(5));
        assert!(!w.accept(5));
        assert!(w.accept(3));
        assert!(!w.accept(3));
        assert!(w.accept(100));
        assert!(!w.accept(5)); // too old (100-5 >= 64)
        assert!(w.accept(99));
        assert!(w.accept(37)); // 100-37 = 63 < 64
        assert!(!w.accept(36));
        assert!(w.accept(1000));
        assert!(!w.accept(100));
    }

    #[test]
    fn zero_counter_first_message() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0));
        assert!(!w.accept(0));
        assert!(w.accept(1));
    }
}
