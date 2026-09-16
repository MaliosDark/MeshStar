//! Forwarding policy engine.

use alloc::string::String;
use alloc::vec::Vec;

use crate::model::{ContentType, ProtocolId, SecurityLevel, UnifiedMessage};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RuleAction {
    Allow,
    #[default]
    Deny,
}

/// One rule. `None` matches anything.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Rule {
    pub from: Option<ProtocolId>,
    pub to: Option<ProtocolId>,
    /// Channel name (exact) or "*".
    pub channel: Option<String>,
    pub content: Option<ContentTypeMatch>,
    /// Canonical identity string of the source, or a prefix ending in '*'.
    pub identity: Option<String>,
    /// Only messages whose security level is at most this "openness".
    pub security: Option<SecurityMatch>,
    pub action: RuleAction,
    pub name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ContentTypeMatch {
    Text,
    Position,
    Binary,
    Any,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SecurityMatch {
    /// Plaintext or shared-key channels ("public" traffic).
    PublicOnly,
    /// Anything except MeshStar end-to-end / envelope traffic.
    NotMeshStarE2E,
    Any,
}

impl Rule {
    pub fn allow(from: ProtocolId, to: ProtocolId) -> Self {
        Self { from: Some(from), to: Some(to), action: RuleAction::Allow, name: alloc::format!("allow {}->{}", from, to), ..Default::default() }
    }
    pub fn deny(from: ProtocolId, to: ProtocolId) -> Self {
        Self { from: Some(from), to: Some(to), action: RuleAction::Deny, name: alloc::format!("deny {}->{}", from, to), ..Default::default() }
    }
    pub fn channel(mut self, ch: &str) -> Self {
        self.channel = Some(ch.into());
        self
    }
    pub fn content(mut self, c: ContentTypeMatch) -> Self {
        self.content = Some(c);
        self
    }
    pub fn security(mut self, s: SecurityMatch) -> Self {
        self.security = Some(s);
        self
    }
    pub fn named(mut self, n: &str) -> Self {
        self.name = n.into();
        self
    }

    fn matches(&self, msg: &UnifiedMessage, to: ProtocolId) -> bool {
        if let Some(f) = self.from {
            if msg.protocol != f {
                return false;
            }
        }
        if let Some(t) = self.to {
            if to != t {
                return false;
            }
        }
        if let Some(ch) = &self.channel {
            if ch != "*" && msg.channel.as_deref() != Some(ch.as_str()) {
                return false;
            }
        }
        if let Some(c) = self.content {
            let ok = match c {
                ContentTypeMatch::Text => msg.content_type == ContentType::Text,
                ContentTypeMatch::Position => msg.content_type == ContentType::Position,
                ContentTypeMatch::Binary => msg.content_type == ContentType::Binary,
                ContentTypeMatch::Any => true,
            };
            if !ok {
                return false;
            }
        }
        if let Some(id) = &self.identity {
            let canon = msg.source.canonical();
            let ok = if let Some(prefix) = id.strip_suffix('*') { canon.starts_with(prefix) } else { canon == *id };
            if !ok {
                return false;
            }
        }
        if let Some(s) = self.security {
            let ok = match s {
                SecurityMatch::Any => true,
                SecurityMatch::NotMeshStarE2E => !msg.security.is_meshstar_e2e(),
                SecurityMatch::PublicOnly => matches!(msg.security, SecurityLevel::Plaintext | SecurityLevel::ForeignSharedKey { .. } | SecurityLevel::MeshStarGroup),
            };
            if !ok {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub rule: Option<String>,
}

/// Ordered rules, first match wins, default deny.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Policy {
    pub rules: Vec<Rule>,
}

impl Policy {
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Public text on shared channels may cross in any direction; MeshStar
    /// private traffic never leaves.
    pub fn public_text_bridging() -> Self {
        let mut p = Self::default();
        p.rules.push(Rule { action: RuleAction::Allow, name: "allow public text".into(), ..Default::default() }.content(ContentTypeMatch::Text).security(SecurityMatch::PublicOnly));
        p.rules.push(Rule { action: RuleAction::Allow, name: "allow public position".into(), ..Default::default() }.content(ContentTypeMatch::Position).security(SecurityMatch::PublicOnly));
        p.rules.push(Rule { action: RuleAction::Deny, name: "deny everything else (encrypted-private, binary)".into(), ..Default::default() });
        p
    }

    pub fn evaluate(&self, msg: &UnifiedMessage, to: ProtocolId) -> PolicyDecision {
        for r in &self.rules {
            if r.matches(msg, to) {
                return PolicyDecision { allowed: r.action == RuleAction::Allow, rule: Some(r.name.clone()) };
            }
        }
        PolicyDecision { allowed: false, rule: None }
    }

    /// Parse the compact textual form used by the CLI / config, e.g.
    /// `allow meshtastic -> meshstar`, `deny meshstar -> *`,
    /// `allow * -> * channel=LongFast content=text security=public`.
    pub fn parse_rule(line: &str) -> Option<Rule> {
        let mut it = line.split_whitespace();
        let action = match it.next()? {
            "allow" => RuleAction::Allow,
            "deny" => RuleAction::Deny,
            _ => return None,
        };
        let from = it.next()?;
        if it.next()? != "->" {
            return None;
        }
        let to = it.next()?;
        let parse_proto = |s: &str| if s == "*" { Some(None) } else { ProtocolId::parse(s).map(Some) };
        let mut r = Rule { from: parse_proto(from)?, to: parse_proto(to)?, action, name: line.into(), ..Default::default() };
        for kv in it {
            let (k, v) = kv.split_once('=')?;
            match k {
                "channel" => r.channel = Some(v.into()),
                "content" => {
                    r.content = Some(match v {
                        "text" => ContentTypeMatch::Text,
                        "position" => ContentTypeMatch::Position,
                        "binary" => ContentTypeMatch::Binary,
                        _ => ContentTypeMatch::Any,
                    })
                }
                "identity" => r.identity = Some(v.into()),
                "security" => {
                    r.security = Some(match v {
                        "public" => SecurityMatch::PublicOnly,
                        "not-e2e" => SecurityMatch::NotMeshStarE2E,
                        _ => SecurityMatch::Any,
                    })
                }
                _ => return None,
            }
        }
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::IdentityRef;

    fn msg(p: ProtocolId, sec: SecurityLevel) -> UnifiedMessage {
        let mut m = UnifiedMessage::text(IdentityRef::Meshtastic(1), IdentityRef::Broadcast(p), p, "hi");
        m.security = sec;
        m.channel = Some("LongFast".into());
        m
    }

    #[test]
    fn default_deny_and_public_policy() {
        let p = Policy::deny_all();
        assert!(!p.evaluate(&msg(ProtocolId::Meshtastic, SecurityLevel::Plaintext), ProtocolId::MeshStar).allowed);
        let p = Policy::public_text_bridging();
        assert!(p.evaluate(&msg(ProtocolId::Meshtastic, SecurityLevel::ForeignSharedKey { protocol: ProtocolId::Meshtastic, channel: "LongFast".into() }), ProtocolId::MeshStar).allowed);
        assert!(!p.evaluate(&msg(ProtocolId::MeshStar, SecurityLevel::MeshStarE2E), ProtocolId::Meshtastic).allowed);
        assert!(p.evaluate(&msg(ProtocolId::MeshStar, SecurityLevel::MeshStarGroup), ProtocolId::Meshtastic).allowed);
        let mut bin = msg(ProtocolId::Meshtastic, SecurityLevel::Plaintext);
        bin.content_type = ContentType::Binary;
        assert!(!p.evaluate(&bin, ProtocolId::MeshStar).allowed);
    }

    #[test]
    fn parse_rules() {
        let r = Policy::parse_rule("allow meshtastic -> meshstar channel=LongFast content=text security=public").unwrap();
        assert_eq!(r.from, Some(ProtocolId::Meshtastic));
        assert_eq!(r.to, Some(ProtocolId::MeshStar));
        assert_eq!(r.channel.as_deref(), Some("LongFast"));
        let mut p = Policy::default();
        p.rules.push(Policy::parse_rule("deny meshstar -> *").unwrap());
        p.rules.push(Policy::parse_rule("allow * -> *").unwrap());
        assert!(!p.evaluate(&msg(ProtocolId::MeshStar, SecurityLevel::Plaintext), ProtocolId::MeshCore).allowed);
        assert!(p.evaluate(&msg(ProtocolId::MeshCore, SecurityLevel::Plaintext), ProtocolId::MeshStar).allowed);
        assert!(Policy::parse_rule("permit a -> b").is_none());
    }
}
