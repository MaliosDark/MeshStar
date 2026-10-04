#![no_main]
//! Foreign Meshtastic frames: header and protobuf payloads from the air.
use libfuzzer_sys::fuzz_target;
use meshstar_protocols::meshtastic::{header::PacketHeader, proto};

fuzz_target!(|data: &[u8]| {
    let _ = PacketHeader::parse(data);
    let _ = proto::Data::decode(data);
    let _ = proto::User::decode(data);
    let _ = proto::Position::decode(data);
    let _ = proto::Routing::decode(data);
});
