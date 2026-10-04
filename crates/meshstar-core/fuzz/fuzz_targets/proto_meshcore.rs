#![no_main]
//! Foreign MeshCore frames: packet framing and identity adverts from the air.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = meshstar_protocols::meshcore::Packet::parse(data);
    let _ = meshstar_protocols::meshcore::Advert::parse(data);
});
