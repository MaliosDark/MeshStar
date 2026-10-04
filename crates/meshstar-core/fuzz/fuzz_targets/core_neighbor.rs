#![no_main]
//! Neighbor beacons: the most frequently received frame in a dense mesh.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = meshstar_core::neighbor::Beacon::decode(data);
});
