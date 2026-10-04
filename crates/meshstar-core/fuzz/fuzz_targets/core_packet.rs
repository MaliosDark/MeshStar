#![no_main]
//! The main on-air decoder: a raw frame straight off the radio.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // No network key, generous TTL bound: decode must never panic on garbage.
    let _ = meshstar_core::packet::Packet::decode(data, None, 32);
});
