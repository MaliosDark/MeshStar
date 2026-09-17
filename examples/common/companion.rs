//! Companion protocol service: answers app requests from the node, the UI
//! model and the compatibility layer, and turns node events into
//! asynchronous frames. Transport-agnostic: the firmware feeds it bytes from
//! BLE (or serial) and sends back whatever `take_outgoing()` returns.

use alloc::string::String;
use alloc::vec::Vec;

use meshstar_companion::{err, req, Delivery, Event, Framer, Message, Mode, Network, NodeEntry, NodeId, NodeInfo, Proto, Request, Response, Security, Status};
use meshstar_core::identity::Address;
use meshstar_core::node::{FailReason, Node, NodeEvent};
use meshstar_core::protocol::{Reliability, Role};
use meshstar_core::radio::RadioStats;
use meshstar_protocols::model::{IdentityRef, MeshCoreId, ProtocolId};

use crate::ui::{self, Sec, UiModel};

/// What the firmware must do after handling a request (things the service
/// cannot do by itself).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompanionAction {
    None,
    SetMode(Mode),
    Announce,
    Reboot,
    SetTime(u32),
    SetName(String),
    GetSettings,
    SetSettings(meshstar_companion::Settings),
    /// Store and broadcast our position (both 0 clears it).
    SetPosition(i32, i32),
    Trace(Address),
}

/// A text the app wants sent on a foreign network (the firmware encodes it
/// with the compat layer).
pub struct ForeignSend {
    pub proto: ProtocolId,
    pub text: String,
    pub handle: u32,
}

pub struct Companion {
    framer: Framer,
    out: Vec<u8>,
    pub firmware: &'static str,
    pub mode: Mode,
    /// Messages already pushed to the app (by seq), so history and live
    /// delivery do not duplicate.
    last_pushed_seq: u32,
    next_foreign_handle: u32,
}

impl Companion {
    pub fn new(firmware: &'static str) -> Self {
        Self { framer: Framer::new(600), out: Vec::new(), firmware, mode: Mode::Native, last_pushed_seq: 0, next_foreign_handle: 0x8000_0000 }
    }

    /// Bytes to transmit to the app (drained).
    pub fn take_outgoing(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.out)
    }

    pub fn has_outgoing(&self) -> bool {
        !self.out.is_empty()
    }

    fn push(&mut self, r: Response) {
        self.out.extend_from_slice(&r.encode());
    }

    /// Feed received bytes; handles every complete request. Returns actions
    /// for the firmware and foreign sends.
    pub fn feed(&mut self, bytes: &[u8], node: &mut Node, model: &UiModel, radio: &RadioStats, battery_mv: Option<u32>, uptime_s: u64) -> (Vec<CompanionAction>, Vec<ForeignSend>) {
        let mut actions = Vec::new();
        let mut foreign = Vec::new();
        for frame in self.framer.push(bytes) {
            match Request::decode(&frame) {
                Ok(r) => {
                    let (a, f) = self.handle(r, node, model, radio, battery_mv, uptime_s);
                    if a != CompanionAction::None {
                        actions.push(a);
                    }
                    if let Some(f) = f {
                        foreign.push(f);
                    }
                }
                Err(e) => self.push(Response::Error { code: err::BAD_FRAME, text: alloc::format!("{:?}", e) }),
            }
        }
        (actions, foreign)
    }

    fn handle(&mut self, r: Request, node: &mut Node, model: &UiModel, radio: &RadioStats, battery_mv: Option<u32>, uptime_s: u64) -> (CompanionAction, Option<ForeignSend>) {
        match r {
            Request::GetInfo => {
                let p = node.config().profile;
                self.push(Response::Info(NodeInfo {
                    name: String::from(model.name.as_str()),
                    id: NodeId::MeshStar(node.address().0),
                    public_key: node.identity().public().public_key_bytes(),
                    role: node.role() as u8,
                    firmware: String::from(self.firmware),
                    frequency_hz: p.frequency_hz,
                    bandwidth_hz: p.bandwidth_hz,
                    spreading_factor: p.spreading_factor,
                    coding_rate: p.coding_rate,
                    tx_power_dbm: p.tx_power_dbm,
                    capabilities: 1 | 2 | 4 | 16,
                }));
            }
            Request::GetNodes => {
                let now = node.diagnostics().now;
                for n in model.nodes.iter() {
                    let mut flags = 0u8;
                    if n.sleeping {
                        flags |= 1;
                    }
                    if n.anchor {
                        flags |= 2;
                    }
                    if n.sec == Sec::E2e {
                        flags |= 4;
                    }
                    self.push(Response::Node(NodeEntry { id: to_node_id(&n.key), name: String::from(n.name.as_str()), rssi_dbm: n.rssi, snr_q: 0, security: to_security(n.sec), hops: n.hops, flags, last_seen_s: (now.saturating_sub(n.last_seen) / 1000) as u32, lat_e7: n.lat_e7, lon_e7: n.lon_e7 }));
                }
                self.push(Response::End { kind: req::GET_NODES });
            }
            Request::SendText { to, reliability, text } => match to {
                NodeId::MeshStar(a) => {
                    let rel = match reliability {
                        0 => Reliability::Unreliable,
                        2 => Reliability::StoreAndForward,
                        _ => Reliability::Acknowledged,
                    };
                    match node.send_message(Address(a), text.as_bytes(), rel) {
                        Ok(h) => self.push(Response::SendResult { handle: h, accepted: true, reason: 0 }),
                        Err(_) => self.push(Response::SendResult { handle: 0, accepted: false, reason: err::QUEUE_FULL }),
                    }
                }
                NodeId::Broadcast(Proto::MeshStar) => match node.send_broadcast(text.as_bytes()) {
                    Ok(h) => self.push(Response::SendResult { handle: h, accepted: true, reason: 0 }),
                    Err(_) => self.push(Response::SendResult { handle: 0, accepted: false, reason: err::QUEUE_FULL }),
                },
                NodeId::Broadcast(Proto::Meshtastic) | NodeId::Meshtastic(_) => {
                    let handle = self.foreign_handle();
                    self.push(Response::SendResult { handle, accepted: true, reason: 0 });
                    return (CompanionAction::None, Some(ForeignSend { proto: ProtocolId::Meshtastic, text, handle }));
                }
                NodeId::Broadcast(Proto::MeshCore) | NodeId::MeshCore(_) => {
                    let handle = self.foreign_handle();
                    self.push(Response::SendResult { handle, accepted: true, reason: 0 });
                    return (CompanionAction::None, Some(ForeignSend { proto: ProtocolId::MeshCore, text, handle }));
                }
                NodeId::Broadcast(Proto::Unknown) => self.push(Response::SendResult { handle: 0, accepted: false, reason: err::UNSUPPORTED }),
            },
            Request::GetNetworks => {
                let now = node.diagnostics().now;
                for n in model.nets.iter() {
                    self.push(Response::Network(Network { proto: to_proto(n.proto), name: String::from(n.name.as_str()), nodes: n.nodes, rssi_dbm: n.rssi, frames: n.frames, last_seen_s: if n.last_seen == 0 { u32::MAX } else { (now.saturating_sub(n.last_seen) / 1000) as u32 } }));
                }
                self.push(Response::End { kind: req::GET_NETWORKS });
            }
            Request::SetMode(m) => {
                self.mode = m;
                self.push_status(node, model, radio, battery_mv, uptime_s);
                return (CompanionAction::SetMode(m), None);
            }
            Request::GetStatus => self.push_status(node, model, radio, battery_mv, uptime_s),
            Request::SetName(name) => {
                let name: String = name.chars().filter(|c| !c.is_control()).take(31).collect();
                if name.trim().is_empty() {
                    self.push(Response::Error { code: err::BAD_FRAME, text: "empty name".into() });
                } else {
                    self.push(Response::End { kind: req::SET_NAME });
                    return (CompanionAction::SetName(name), None);
                }
            }
            Request::SetRole(_) => self.push(Response::Error { code: err::UNSUPPORTED, text: "role is set at build time for now".into() }),
            Request::Announce => {
                self.push(Response::End { kind: req::ANNOUNCE });
                return (CompanionAction::Announce, None);
            }
            Request::GetMessages { after_seq } => {
                let now = node.diagnostics().now;
                for m in model.msgs.iter().rev() {
                    if m.seq > after_seq {
                        self.push(Response::Message(to_message(m, now)));
                        self.last_pushed_seq = self.last_pushed_seq.max(m.seq);
                    }
                }
                self.push(Response::End { kind: req::GET_MESSAGES });
            }
            Request::SetTime { unix_s } => {
                self.push(Response::End { kind: req::SET_TIME });
                return (CompanionAction::SetTime(unix_s), None);
            }
            Request::Reboot => return (CompanionAction::Reboot, None),
            Request::GetSettings => return (CompanionAction::GetSettings, None),
            Request::SetPosition { lat_e7, lon_e7 } => {
                self.push(Response::End { kind: req::SET_POSITION });
                return (CompanionAction::SetPosition(lat_e7, lon_e7), None);
            }
            Request::Trace { to } => match to {
                NodeId::MeshStar(a) => match node.trace(Address(a)) {
                    Ok(()) => return (CompanionAction::Trace(Address(a)), None),
                    Err(_) => self.push(Response::Trace { to, reached: false, hops: Vec::new(), rtt_ms: 0 }),
                },
                _ => self.push(Response::Error { code: err::UNSUPPORTED, text: "trace is a MeshStar feature".into() }),
            },
            Request::SetSettings(st) => {
                let name: String = st.name.chars().filter(|c| !c.is_control()).take(31).collect();
                if name.trim().is_empty() || st.role > 2 || st.profile > 3 || !(-9..=22).contains(&st.tx_power_dbm) || !(30..=3600).contains(&st.beacon_interval_s) {
                    self.push(Response::Error { code: err::BAD_FRAME, text: "settings out of range".into() });
                } else {
                    self.push(Response::End { kind: req::SET_SETTINGS });
                    return (CompanionAction::SetSettings(meshstar_companion::Settings { name, ..st }), None);
                }
            }
            Request::Ping(n) => self.push(Response::Pong(n)),
        }
        (CompanionAction::None, None)
    }

    fn foreign_handle(&mut self) -> u32 {
        self.next_foreign_handle = self.next_foreign_handle.wrapping_add(1);
        self.next_foreign_handle
    }

    fn push_status(&mut self, node: &mut Node, model: &UiModel, radio: &RadioStats, battery_mv: Option<u32>, uptime_s: u64) {
        let d = node.diagnostics();
        self.push(Response::Status(Status {
            mode: self.mode,
            battery_mv: battery_mv.unwrap_or(0) as u16,
            uptime_s: uptime_s as u32,
            neighbors: d.neighbors.len() as u8,
            zone: d.zone.len() as u8,
            sessions: d.sessions.len() as u8,
            rx_frames: radio.rx_frames,
            tx_frames: radio.tx_frames,
            duty_permille: d.airtime_permille,
            unread: model.unread() as u8,
            last_rssi_dbm: radio.last_rssi_dbm,
            last_snr_q: (radio.last_snr_db * 4.0) as i8,
        }));
    }

    /// Push every message the app has not seen yet (call after the model
    /// changed).
    pub fn push_new_messages(&mut self, model: &UiModel, now: u64) {
        let mut newest = self.last_pushed_seq;
        for m in model.msgs.iter().rev() {
            if m.seq > self.last_pushed_seq {
                self.push(Response::Message(to_message(m, now)));
                newest = newest.max(m.seq);
            }
        }
        self.last_pushed_seq = newest;
    }

    /// Mirror a node event to the app.
    pub fn on_event(&mut self, ev: &NodeEvent) {
        let r = match ev {
            NodeEvent::Delivered { handle, .. } => Response::DeliveryUpdate { handle: *handle, state: Delivery::Delivered, reason: 0 },
            NodeEvent::Stored { handle, .. } => Response::DeliveryUpdate { handle: *handle, state: Delivery::Stored, reason: 0 },
            NodeEvent::Failed { handle, reason, .. } => Response::DeliveryUpdate { handle: *handle, state: Delivery::Failed, reason: fail_code(*reason) },
            NodeEvent::NeighborUp(a) => Response::Event(Event::NeighborUp(NodeId::MeshStar(a.0))),
            NodeEvent::NeighborDown(a) => Response::Event(Event::NeighborDown(NodeId::MeshStar(a.0))),
            NodeEvent::SessionEstablished(a) => Response::Event(Event::SessionEstablished(NodeId::MeshStar(a.0))),
            NodeEvent::RouteFound { dst, hops, .. } => Response::Event(Event::RouteFound { dst: NodeId::MeshStar(dst.0), hops: *hops }),
            NodeEvent::RouteLost(a) => Response::Event(Event::RouteLost(NodeId::MeshStar(a.0))),
            _ => return,
        };
        self.push(r);
    }

    /// A trace finished: resolve the relays' short ids against what the
    /// node knows (unknown ones are sent as `00..00xxxx`).
    pub fn on_trace(&mut self, node: &Node, dst: Address, reached: bool, hops: &[u16], rtt_ms: u64) {
        let resolve = |s: u16| -> NodeId {
            if let Some(n) = node.neighbors().iter().find(|n| n.addr.short() == s) {
                return NodeId::MeshStar(n.addr.0);
            }
            if let Some(z) = node.zone().iter().find(|z| z.addr.short() == s) {
                return NodeId::MeshStar(z.addr.0);
            }
            if let Some(r) = node.routes().iter().find(|r| r.dst.short() == s) {
                return NodeId::MeshStar(r.dst.0);
            }
            let b = s.to_be_bytes();
            NodeId::MeshStar([0, 0, 0, 0, 0, 0, b[0], b[1]])
        };
        self.push(Response::Trace { to: NodeId::MeshStar(dst.0), reached, hops: hops.iter().map(|s| resolve(*s)).collect(), rtt_ms: rtt_ms as u32 });
    }

    /// Report a foreign send as done (sent on air; foreign networks have no
    /// end-to-end ack we can observe).
    pub fn foreign_sent(&mut self, handle: u32, ok: bool) {
        self.push(Response::DeliveryUpdate { handle, state: if ok { Delivery::Sent } else { Delivery::Failed }, reason: if ok { 0 } else { err::BUSY } });
    }

    /// Answer GET_SETTINGS.
    pub fn settings(&mut self, st: &meshstar_companion::Settings) {
        self.push(Response::Settings(st.clone()));
    }

    pub fn mode_changed(&mut self, mode: Mode) {
        self.mode = mode;
        self.push(Response::Event(Event::ModeChanged(mode)));
    }
}

fn fail_code(r: FailReason) -> u8 {
    match r {
        FailReason::NoRoute => err::NO_ROUTE,
        FailReason::QueueFull => err::QUEUE_FULL,
        FailReason::NoAck => 10,
        FailReason::NoSession => 11,
        FailReason::NoKey => 12,
        FailReason::TooLarge => 13,
        FailReason::Rejected => 14,
    }
}

pub fn to_node_id(r: &IdentityRef) -> NodeId {
    match r {
        IdentityRef::MeshStar(a) => NodeId::MeshStar(a.0),
        IdentityRef::Meshtastic(n) => NodeId::Meshtastic(*n),
        IdentityRef::MeshCore(MeshCoreId::PublicKey(k)) => NodeId::MeshCore(k.to_vec()),
        IdentityRef::MeshCore(MeshCoreId::HashPrefix(h)) => NodeId::MeshCore(h.clone()),
        IdentityRef::Broadcast(p) => NodeId::Broadcast(to_proto(ui::Proto::from_id(*p))),
    }
}

fn to_proto(p: ui::Proto) -> Proto {
    match p {
        ui::Proto::Star => Proto::MeshStar,
        ui::Proto::Meshtastic => Proto::Meshtastic,
        ui::Proto::MeshCore => Proto::MeshCore,
        ui::Proto::Unknown => Proto::Unknown,
    }
}

fn to_security(s: Sec) -> Security {
    match s {
        Sec::E2e => Security::E2e,
        Sec::Envelope => Security::Envelope,
        Sec::Group => Security::Group,
        Sec::Channel => Security::Channel,
        Sec::Direct => Security::Direct,
        Sec::Bridged => Security::Bridged,
        Sec::Plain => Security::Plain,
        Sec::Opaque => Security::Opaque,
        Sec::None => Security::None,
    }
}

fn to_message(m: &ui::UiMsg, now: u64) -> Message {
    Message { seq: m.seq, from: to_node_id(&m.from_id), from_name: String::from(m.from.as_str()), channel: String::from(m.channel.as_str()), text: String::from(m.text.as_str()), security: to_security(m.sec), rssi_dbm: m.rssi, snr_q: 0, hops: m.hops, age_s: (now.saturating_sub(m.at) / 1000) as u32, via: String::from(m.via.as_str()) }
}

#[allow(dead_code)]
fn _role_name(r: Role) -> &'static str {
    r.name()
}
