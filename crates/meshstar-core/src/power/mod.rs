//! Energy management: regulatory duty cycle, sleep scheduling and the
//! LEAF low-power behaviour.
//!
//! The core never assumes every node is awake. A LEAF wakes every
//! `wake_interval`, listens/transmits during an `awake_window` (extended
//! while traffic is flowing), announces itself with a beacon so its ANCHOR
//! can flush the mailbox, then sleeps. NORMAL/ANCHOR nodes may still duty
//! cycle their receiver between beacon intervals.

/// Operating mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PowerMode {
    /// Receiver always on (ANCHOR, mains powered NORMAL).
    AlwaysOn,
    /// Receiver on for `listen_ms` then off for `sleep_ms` (battery NORMAL).
    DutyCycle { listen_ms: u32, sleep_ms: u32 },
    /// LEAF: sleep `wake_interval_s`, stay awake `awake_window_ms`.
    Leaf { wake_interval_s: u16, awake_window_ms: u16 },
}

/// Configuration.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct PowerConfig {
    pub mode: PowerMode,
    /// Regulatory transmit duty cycle limit in tenths of a percent over the
    /// window (EU 868 g1: 1 % => 10).
    pub max_airtime_permille: u16,
    pub airtime_window_ms: u64,
    /// Beacon interval multiplier when the neighbourhood is stable
    /// (adaptive control traffic): 1 = never slow down.
    pub max_beacon_slowdown: u8,
    /// Traffic keeps a LEAF awake this long after the last packet.
    pub activity_extension_ms: u32,
}

impl Default for PowerConfig {
    fn default() -> Self {
        Self { mode: PowerMode::AlwaysOn, max_airtime_permille: 10, airtime_window_ms: 3_600_000, max_beacon_slowdown: 4, activity_extension_ms: 3_000 }
    }
}

/// Runtime power state.
#[derive(Debug)]
pub struct PowerManager {
    cfg: PowerConfig,
    /// (timestamp, airtime ms) of recent transmissions.
    tx_log: alloc::collections::VecDeque<(u64, u32)>,
    airtime_in_window: u64,
    awake: bool,
    awake_until: u64,
    next_wake: u64,
    /// Beacon intervals without neighbour change.
    stable_intervals: u8,
    pub stats: PowerStats,
}

#[derive(Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct PowerStats {
    pub tx_airtime_ms: u64,
    pub sleep_ms: u64,
    pub wakeups: u32,
    pub tx_deferred_duty: u32,
}

impl PowerManager {
    pub fn new(cfg: PowerConfig, now: u64) -> Self {
        Self { cfg, tx_log: alloc::collections::VecDeque::new(), airtime_in_window: 0, awake: true, awake_until: u64::MAX, next_wake: now, stable_intervals: 0, stats: PowerStats::default() }
    }

    pub fn config(&self) -> &PowerConfig {
        &self.cfg
    }

    pub fn mode(&self) -> PowerMode {
        self.cfg.mode
    }

    fn prune(&mut self, now: u64) {
        while let Some((t, a)) = self.tx_log.front() {
            if now.saturating_sub(*t) > self.cfg.airtime_window_ms {
                self.airtime_in_window -= *a as u64;
                self.tx_log.pop_front();
            } else {
                break;
            }
        }
    }

    /// Whether a transmission of `airtime_ms` fits the regulatory budget.
    pub fn can_transmit(&mut self, now: u64, airtime_ms: u32) -> bool {
        self.prune(now);
        let budget = self.cfg.airtime_window_ms * self.cfg.max_airtime_permille as u64 / 1000;
        let ok = self.airtime_in_window + airtime_ms as u64 <= budget;
        if !ok {
            self.stats.tx_deferred_duty += 1;
        }
        ok
    }

    pub fn record_tx(&mut self, now: u64, airtime_ms: u32) {
        self.prune(now);
        self.tx_log.push_back((now, airtime_ms));
        self.airtime_in_window += airtime_ms as u64;
        self.stats.tx_airtime_ms += airtime_ms as u64;
        if self.tx_log.len() > 4096 {
            if let Some((_, a)) = self.tx_log.pop_front() {
                self.airtime_in_window -= a as u64;
            }
        }
    }

    /// Airtime used in the window, permille of the window.
    pub fn airtime_permille(&mut self, now: u64) -> u16 {
        self.prune(now);
        (self.airtime_in_window * 1000 / self.cfg.airtime_window_ms.max(1)) as u16
    }

    pub fn is_awake(&self) -> bool {
        self.awake
    }

    pub fn awake_until(&self) -> u64 {
        self.awake_until
    }

    /// Next scheduled wake-up (only meaningful while asleep).
    pub fn next_wake(&self) -> u64 {
        self.next_wake
    }

    /// Traffic involving us: extend the awake window.
    pub fn on_activity(&mut self, now: u64) {
        if self.awake && self.awake_until != u64::MAX {
            self.awake_until = self.awake_until.max(now + self.cfg.activity_extension_ms as u64);
        }
    }

    /// Advance the schedule. Returns `Some(true)` when we just woke up,
    /// `Some(false)` when we just fell asleep, `None` when unchanged.
    pub fn tick(&mut self, now: u64) -> Option<bool> {
        match self.cfg.mode {
            PowerMode::AlwaysOn => {
                if !self.awake {
                    self.awake = true;
                    self.awake_until = u64::MAX;
                    return Some(true);
                }
                None
            }
            PowerMode::DutyCycle { listen_ms, sleep_ms } => self.step(now, listen_ms as u64, sleep_ms as u64),
            PowerMode::Leaf { wake_interval_s, awake_window_ms } => self.step(now, awake_window_ms as u64, wake_interval_s as u64 * 1000),
        }
    }

    fn step(&mut self, now: u64, awake_len: u64, sleep_len: u64) -> Option<bool> {
        if self.awake {
            if self.awake_until == u64::MAX {
                // first tick after construction: start the window now
                self.awake_until = now + awake_len;
                return None;
            }
            if now >= self.awake_until {
                self.awake = false;
                self.next_wake = now + sleep_len;
                return Some(false);
            }
            None
        } else if now >= self.next_wake {
            self.awake = true;
            self.awake_until = now + awake_len;
            self.stats.sleep_ms += sleep_len;
            self.stats.wakeups += 1;
            Some(true)
        } else {
            None
        }
    }

    /// Force wake (button press, sensor event) for `window_ms`.
    pub fn wake_now(&mut self, now: u64, window_ms: u32) {
        if !self.awake {
            self.stats.wakeups += 1;
        }
        self.awake = true;
        self.awake_until = now + window_ms as u64;
    }

    /// Time until the next state change (for the platform sleep call).
    pub fn next_event(&self) -> u64 {
        if self.awake {
            self.awake_until
        } else {
            self.next_wake
        }
    }

    /// Adaptive beacon slow-down: call once per beacon interval with
    /// whether the neighbourhood changed; returns the multiplier to apply
    /// to the base beacon interval.
    pub fn beacon_multiplier(&mut self, neighborhood_changed: bool) -> u8 {
        if neighborhood_changed {
            self.stable_intervals = 0;
        } else {
            self.stable_intervals = self.stable_intervals.saturating_add(1);
        }
        let m = 1 + self.stable_intervals / 4;
        m.min(self.cfg.max_beacon_slowdown.max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duty_cycle_budget() {
        let mut p = PowerManager::new(PowerConfig { max_airtime_permille: 10, airtime_window_ms: 10_000, ..Default::default() }, 0);
        // 1% of 10 s = 100 ms
        assert!(p.can_transmit(0, 60));
        p.record_tx(0, 60);
        assert!(!p.can_transmit(1, 50));
        assert!(p.can_transmit(1, 40));
        assert!(p.can_transmit(10_001, 100)); // window slid
        assert_eq!(p.stats.tx_deferred_duty, 1);
    }

    #[test]
    fn leaf_schedule() {
        let mut p = PowerManager::new(PowerConfig { mode: PowerMode::Leaf { wake_interval_s: 10, awake_window_ms: 500 }, activity_extension_ms: 1000, ..Default::default() }, 0);
        assert!(p.is_awake());
        assert_eq!(p.tick(0), None); // window starts
        assert_eq!(p.tick(100), None);
        p.on_activity(400); // extends to 1400
        assert_eq!(p.tick(500), None);
        assert_eq!(p.tick(1400), Some(false));
        assert!(!p.is_awake());
        assert_eq!(p.next_event(), 11_400);
        assert_eq!(p.tick(5000), None);
        assert_eq!(p.tick(11_400), Some(true));
        assert_eq!(p.stats.wakeups, 1);
        p.tick(11_900);
        assert!(!p.is_awake());
        p.wake_now(12_000, 200);
        assert!(p.is_awake());
        assert_eq!(p.tick(12_200), Some(false));
    }

    #[test]
    fn beacon_slowdown() {
        let mut p = PowerManager::new(PowerConfig { max_beacon_slowdown: 3, ..Default::default() }, 0);
        assert_eq!(p.beacon_multiplier(false), 1);
        for _ in 0..3 {
            p.beacon_multiplier(false);
        }
        assert_eq!(p.beacon_multiplier(false), 2);
        for _ in 0..20 {
            p.beacon_multiplier(false);
        }
        assert_eq!(p.beacon_multiplier(false), 3);
        assert_eq!(p.beacon_multiplier(true), 1);
    }
}
