//! Platform services the core needs but does not implement: time, entropy
//! and persistent storage. Firmware, simulator and CLI provide them.

use alloc::vec::Vec;

pub mod nvs;

/// Monotonic millisecond clock.
pub trait Clock {
    fn now_ms(&self) -> u64;
}

/// Small key/value persistence (identity seed, node config, mailbox).
pub trait Storage {
    fn load(&mut self, key: &str) -> Option<Vec<u8>>;
    fn store(&mut self, key: &str, value: &[u8]) -> bool;
    fn remove(&mut self, key: &str) -> bool;
}

/// Volatile storage (tests, simulator).
#[derive(Debug, Default)]
pub struct MemoryStorage {
    map: alloc::collections::BTreeMap<alloc::string::String, Vec<u8>>,
}

impl Storage for MemoryStorage {
    fn load(&mut self, key: &str) -> Option<Vec<u8>> {
        self.map.get(key).cloned()
    }
    fn store(&mut self, key: &str, value: &[u8]) -> bool {
        self.map.insert(key.into(), value.to_vec());
        true
    }
    fn remove(&mut self, key: &str) -> bool {
        self.map.remove(key).is_some()
    }
}

/// Deterministic seedable CSPRNG used everywhere in the core.
pub type Rng = rand_chacha::ChaCha20Rng;

/// Build the core RNG from platform entropy (hardware RNG, seed file, ...).
pub fn rng_from_seed(seed: [u8; 32]) -> Rng {
    use rand_core::SeedableRng;
    Rng::from_seed(seed)
}

#[cfg(feature = "std")]
pub mod std_impl {
    //! Implementations backed by the Rust standard library.
    use super::*;
    use std::time::Instant;

    /// Wall clock based monotonic clock.
    #[derive(Debug)]
    pub struct StdClock(Instant);

    impl Default for StdClock {
        fn default() -> Self {
            Self(Instant::now())
        }
    }

    impl Clock for StdClock {
        fn now_ms(&self) -> u64 {
            self.0.elapsed().as_millis() as u64
        }
    }

    /// Directory backed storage, one file per key.
    #[derive(Debug)]
    pub struct DirStorage {
        pub dir: std::path::PathBuf,
    }

    impl DirStorage {
        pub fn new(dir: impl Into<std::path::PathBuf>) -> Self {
            let dir = dir.into();
            let _ = std::fs::create_dir_all(&dir);
            Self { dir }
        }
        fn path(&self, key: &str) -> std::path::PathBuf {
            let safe: String = key.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
            self.dir.join(safe)
        }
    }

    impl Storage for DirStorage {
        fn load(&mut self, key: &str) -> Option<Vec<u8>> {
            std::fs::read(self.path(key)).ok()
        }
        fn store(&mut self, key: &str, value: &[u8]) -> bool {
            std::fs::write(self.path(key), value).is_ok()
        }
        fn remove(&mut self, key: &str) -> bool {
            std::fs::remove_file(self.path(key)).is_ok()
        }
    }

    /// Seed from the OS entropy source.
    pub fn os_rng() -> Rng {
        use std::io::Read;
        let mut seed = [0u8; 32];
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let _ = f.read_exact(&mut seed);
        } else {
            // Fallback: hash time + pid. Only for platforms without /dev/urandom.
            use sha2::Digest;
            let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
            let mut h = sha2::Sha256::new();
            h.update(t.to_le_bytes());
            h.update(std::process::id().to_le_bytes());
            seed = h.finalize().into();
        }
        rng_from_seed(seed)
    }
}
