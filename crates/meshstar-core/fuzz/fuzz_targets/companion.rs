#![no_main]
//! The companion protocol over BLE, and the thumbnail image codec.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = meshstar_companion::Request::decode(data);
    let _ = meshstar_companion::Response::decode(data);
    let _ = meshstar_companion::thumb::decode(data);
});
