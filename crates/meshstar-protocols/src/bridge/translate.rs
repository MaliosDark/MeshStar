//! Conservative translation between protocols.
//!
//! Only what both sides can express is translated (see the capability
//! matrix in `docs/INTEROP.md`). Anything else fails safely or is degraded
//! with explicit metadata, never silently invented.

use alloc::string::String;
use alloc::vec::Vec;

use crate::adapter::ProtocolCapabilities;
use crate::model::{ContentType, IdentityRef, ProtocolId, SecurityLevel, UnifiedMessage};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TranslationOutcome {
    /// Translated faithfully.
    Exact,
    /// Translated with losses listed here (e.g. "text truncated", "reply link dropped").
    Degraded(Vec<String>),
    /// Cannot be represented.
    Unsupported(String),
}

/// Translate `msg` for transmission on `to` by `gateway`. Returns the
/// outgoing message and how faithful the translation is.
pub fn translate(msg: &UnifiedMessage, to: ProtocolId, caps_to: &ProtocolCapabilities, gateway: &str, now: u64, sender_prefix: bool) -> (Option<UnifiedMessage>, TranslationOutcome) {
    let mut losses = Vec::new();
    let mut out = msg.clone();
    match msg.content_type {
        ContentType::Text => {
            if !caps_to.text {
                return (None, TranslationOutcome::Unsupported("text".into()));
            }
            // Prefix with the origin so the foreign network knows who spoke.
            let mut text = String::new();
            if sender_prefix {
                let who = msg.meta("sender_name").or(msg.meta("long_name")).or(msg.meta("short_name")).map(|s| s.into()).unwrap_or_else(|| short_identity(&msg.source));
                text.push_str(&alloc::format!("[{}] ", who));
            }
            text.push_str(msg.text_payload().unwrap_or(""));
            if text.len() > caps_to.max_text_bytes {
                let mut cut = caps_to.max_text_bytes.saturating_sub(3);
                while cut > 0 && !text.is_char_boundary(cut) {
                    cut -= 1;
                }
                text.truncate(cut);
                text.push_str("...");
                losses.push(alloc::format!("text truncated to {} bytes", caps_to.max_text_bytes));
            }
            out.payload = text.into_bytes();
        }
        ContentType::Position => {
            if !caps_to.position {
                return (None, TranslationOutcome::Unsupported("position".into()));
            }
            // Positions travel as metadata (lat/lon); the target adapter re-encodes.
            if msg.meta("lat").is_none() {
                return (None, TranslationOutcome::Unsupported("position without lat/lon metadata".into()));
            }
        }
        ContentType::Binary => {
            if caps_to.max_binary_bytes == 0 {
                return (None, TranslationOutcome::Unsupported("binary".into()));
            }
            if msg.payload.len() > caps_to.max_binary_bytes {
                return (None, TranslationOutcome::Unsupported(alloc::format!("binary payload {} > {}", msg.payload.len(), caps_to.max_binary_bytes)));
            }
        }
        ContentType::Ack => return (None, TranslationOutcome::Unsupported("acknowledgements are per network".into())),
        other => return (None, TranslationOutcome::Unsupported(alloc::format!("{:?}", other))),
    }
    if msg.reply_to.is_some() && !caps_to.replies {
        losses.push("reply link dropped".into());
        out.reply_to = None;
    }
    if msg.wants_ack && !caps_to.acknowledgements {
        losses.push("ack request dropped".into());
        out.wants_ack = false;
    }
    if !msg.destination.is_broadcast() {
        // Unicast across protocols requires an explicit identity mapping,
        // which the gateway must configure; by default bridged traffic is
        // broadcast on the far side.
        losses.push("unicast destination replaced by broadcast (no identity mapping)".into());
        out.destination = IdentityRef::Broadcast(to);
    } else {
        out.destination = IdentityRef::Broadcast(to);
    }
    out.protocol = to;
    out.encrypted = false;
    out.security = SecurityLevel::Bridged { via: msg.protocol, gateway: gateway.into(), original: alloc::boxed::Box::new(msg.security.clone()) };
    out.set_meta("bridged_from", msg.protocol.name());
    out.set_meta("bridged_source", msg.source.canonical());
    out.set_meta("bridged_at", now.to_string());
    out.message_id = String::new();
    let outcome = if losses.is_empty() { TranslationOutcome::Exact } else { TranslationOutcome::Degraded(losses) };
    (Some(out), outcome)
}

fn short_identity(id: &IdentityRef) -> String {
    let c = id.canonical();
    if c.len() > 24 {
        alloc::format!("{}…", &c[..24])
    } else {
        c
    }
}

use alloc::string::ToString;

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(text: usize, replies: bool) -> ProtocolCapabilities {
        ProtocolCapabilities { text: true, binary: false, replies, channels: true, store_forward: false, e2e_identity: false, forward_secrecy: false, position: false, acknowledgements: true, max_text_bytes: text, max_binary_bytes: 0, max_hops: 7 }
    }

    #[test]
    fn text_is_prefixed_truncated_and_labelled() {
        let mut m = UnifiedMessage::text(IdentityRef::Meshtastic(0x1234), IdentityRef::Broadcast(ProtocolId::Meshtastic), ProtocolId::Meshtastic, "hello world this is long");
        m.set_meta("long_name", "Bob");
        m.reply_to = Some("x".into());
        let (o, out) = translate(&m, ProtocolId::MeshCore, &caps(16, false), "gw", 5, true);
        let o = o.unwrap();
        assert!(o.text_payload().unwrap().starts_with("[Bob] "));
        assert!(o.payload.len() <= 16);
        assert!(matches!(out, TranslationOutcome::Degraded(ref l) if l.len() == 2), "{:?}", out);
        assert!(o.security.crossed_bridge());
        assert_eq!(o.protocol, ProtocolId::MeshCore);
        let mut b = m.clone();
        b.content_type = ContentType::Binary;
        assert!(matches!(translate(&b, ProtocolId::MeshCore, &caps(16, false), "gw", 5, true).1, TranslationOutcome::Unsupported(_)));
    }
}
