//! Meshtastic application port numbers (`portnums.proto`).
//!
//! Only the values are taken from the protobuf definition; whether a port is
//! "text-like" follows `MeshService::isTextPayload` in the firmware.

/// Never valid on air; the firmware treats a decoded `portnum == 0` as a bad PSK.
pub const UNKNOWN_APP: u32 = 0;
/// UTF-8 text, no protobuf wrapping.
pub const TEXT_MESSAGE_APP: u32 = 1;
pub const REMOTE_HARDWARE_APP: u32 = 2;
/// `Position` protobuf.
pub const POSITION_APP: u32 = 3;
/// `User` protobuf.
pub const NODEINFO_APP: u32 = 4;
/// `Routing` protobuf (ACK / NAK / traceroute variants).
pub const ROUTING_APP: u32 = 5;
pub const ADMIN_APP: u32 = 6;
/// Unishox2 compressed text; not emitted by current firmware and not decoded here.
pub const TEXT_MESSAGE_COMPRESSED_APP: u32 = 7;
pub const WAYPOINT_APP: u32 = 8;
pub const AUDIO_APP: u32 = 9;
/// Text, displayed like a text message.
pub const DETECTION_SENSOR_APP: u32 = 10;
/// Text, displayed like a (critical) text message.
pub const ALERT_APP: u32 = 11;
pub const KEY_VERIFICATION_APP: u32 = 12;
pub const REMOTE_SHELL_APP: u32 = 13;
pub const REPLY_APP: u32 = 32;
pub const IP_TUNNEL_APP: u32 = 33;
pub const PAXCOUNTER_APP: u32 = 34;
pub const STORE_FORWARD_PLUSPLUS_APP: u32 = 35;
pub const NODE_STATUS_APP: u32 = 36;
pub const MESH_BEACON_APP: u32 = 37;
pub const PAGING_APP: u32 = 38;
pub const SERIAL_APP: u32 = 64;
pub const STORE_FORWARD_APP: u32 = 65;
pub const RANGE_TEST_APP: u32 = 66;
/// `Telemetry` protobuf (kept opaque by this adapter).
pub const TELEMETRY_APP: u32 = 67;
pub const ZPS_APP: u32 = 68;
pub const SIMULATOR_APP: u32 = 69;
/// `RouteDiscovery` protobuf.
pub const TRACEROUTE_APP: u32 = 70;
pub const NEIGHBORINFO_APP: u32 = 71;
pub const ATAK_PLUGIN: u32 = 72;
pub const MAP_REPORT_APP: u32 = 73;
pub const POWERSTRESS_APP: u32 = 74;
pub const LORAWAN_BRIDGE: u32 = 75;
pub const RETICULUM_TUNNEL_APP: u32 = 76;
pub const CAYENNE_APP: u32 = 77;
pub const ATAK_PLUGIN_V2: u32 = 78;
pub const LORA_OTA_APP: u32 = 79;
pub const GROUPALARM_APP: u32 = 112;
/// Arbitrary application bytes ("private" port). Used here for `ContentType::Binary`.
pub const PRIVATE_APP: u32 = 256;
pub const ATAK_FORWARDER: u32 = 257;
/// Largest port number the enum allows.
pub const MAX: u32 = 511;

/// Symbolic name of a port number, if it is one defined in `portnums.proto`.
pub fn name(port: u32) -> Option<&'static str> {
    Some(match port {
        UNKNOWN_APP => "UNKNOWN_APP",
        TEXT_MESSAGE_APP => "TEXT_MESSAGE_APP",
        REMOTE_HARDWARE_APP => "REMOTE_HARDWARE_APP",
        POSITION_APP => "POSITION_APP",
        NODEINFO_APP => "NODEINFO_APP",
        ROUTING_APP => "ROUTING_APP",
        ADMIN_APP => "ADMIN_APP",
        TEXT_MESSAGE_COMPRESSED_APP => "TEXT_MESSAGE_COMPRESSED_APP",
        WAYPOINT_APP => "WAYPOINT_APP",
        AUDIO_APP => "AUDIO_APP",
        DETECTION_SENSOR_APP => "DETECTION_SENSOR_APP",
        ALERT_APP => "ALERT_APP",
        KEY_VERIFICATION_APP => "KEY_VERIFICATION_APP",
        REMOTE_SHELL_APP => "REMOTE_SHELL_APP",
        REPLY_APP => "REPLY_APP",
        IP_TUNNEL_APP => "IP_TUNNEL_APP",
        PAXCOUNTER_APP => "PAXCOUNTER_APP",
        STORE_FORWARD_PLUSPLUS_APP => "STORE_FORWARD_PLUSPLUS_APP",
        NODE_STATUS_APP => "NODE_STATUS_APP",
        MESH_BEACON_APP => "MESH_BEACON_APP",
        PAGING_APP => "PAGING_APP",
        SERIAL_APP => "SERIAL_APP",
        STORE_FORWARD_APP => "STORE_FORWARD_APP",
        RANGE_TEST_APP => "RANGE_TEST_APP",
        TELEMETRY_APP => "TELEMETRY_APP",
        ZPS_APP => "ZPS_APP",
        SIMULATOR_APP => "SIMULATOR_APP",
        TRACEROUTE_APP => "TRACEROUTE_APP",
        NEIGHBORINFO_APP => "NEIGHBORINFO_APP",
        ATAK_PLUGIN => "ATAK_PLUGIN",
        MAP_REPORT_APP => "MAP_REPORT_APP",
        POWERSTRESS_APP => "POWERSTRESS_APP",
        LORAWAN_BRIDGE => "LORAWAN_BRIDGE",
        RETICULUM_TUNNEL_APP => "RETICULUM_TUNNEL_APP",
        CAYENNE_APP => "CAYENNE_APP",
        ATAK_PLUGIN_V2 => "ATAK_PLUGIN_V2",
        LORA_OTA_APP => "LORA_OTA_APP",
        GROUPALARM_APP => "GROUPALARM_APP",
        PRIVATE_APP => "PRIVATE_APP",
        ATAK_FORWARDER => "ATAK_FORWARDER",
        _ => return None,
    })
}

/// Whether a port carries text that the firmware displays like a text
/// message (`MeshService::isTextPayload`, without the optional RANGE_TEST).
pub fn is_text(port: u32) -> bool {
    matches!(port, TEXT_MESSAGE_APP | DETECTION_SENSOR_APP | ALERT_APP)
}

/// Whether the value is inside the `PortNum` enum range.
pub fn is_valid(port: u32) -> bool {
    port <= MAX
}
