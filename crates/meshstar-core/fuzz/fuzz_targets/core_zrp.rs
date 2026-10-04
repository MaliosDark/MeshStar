#![no_main]
//! Routing control messages carried inside packets.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = meshstar_core::zrp::RouteRequest::decode(data);
    let _ = meshstar_core::zrp::RouteReply::decode(data);
    let _ = meshstar_core::zrp::RouteError::decode(data);
});
