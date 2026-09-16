//! Plaintext / payload formats of the message-carrying MeshCore payload
//! types (`BaseChatMesh.cpp`, `Mesh.cpp createDatagram /
//! createGroupDatagram`, `docs/payloads.md`).
//!
//! * TXT_MSG payload: `dest_hash(1) || src_hash(1) || MAC(2) || ciphertext`;
//!   plaintext `timestamp u32 LE || (txt_type << 2 | attempt & 3) || text || NUL`.
//! * GRP_TXT payload: `channel_hash(1) || MAC(2) || ciphertext`;
//!   plaintext `timestamp u32 LE || 0x00 || "<name>: <message>"`.
//! * GRP_DATA plaintext: `data_type u16 LE || data_len u8 || data`.
//! * ACK payload: 4 bytes (6 in newer firmware; only 4 are compared).

use alloc::string::String;
use alloc::vec::Vec;

use super::crypto::{self, Secret};

/// `MAX_TEXT_LEN` (`BaseChatMesh.h`).
pub const MAX_TEXT_LEN: usize = 160;
/// `MAX_GROUP_DATA_LENGTH` (`MeshCore.h`).
pub const MAX_GROUP_DATA_LENGTH: usize = 165;
/// Header of a direct datagram before the ciphertext.
pub const DATAGRAM_HEADER_LEN: usize = 4;
/// Header of a group datagram before the ciphertext.
pub const GROUP_HEADER_LEN: usize = 3;
/// `TXT_TYPE_PLAIN`.
pub const TXT_TYPE_PLAIN: u8 = 0;
/// `TXT_TYPE_CLI_DATA`.
pub const TXT_TYPE_CLI_DATA: u8 = 1;
/// `TXT_TYPE_SIGNED_PLAIN`.
pub const TXT_TYPE_SIGNED_PLAIN: u8 = 2;

/// A decoded text plaintext (TXT_MSG or GRP_TXT body).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextPlain {
    pub timestamp: u32,
    /// Upper 6 bits of the flags byte.
    pub txt_type: u8,
    /// Lower 2 bits of the flags byte.
    pub attempt: u8,
    /// Author pubkey prefix for `TXT_TYPE_SIGNED_PLAIN`.
    pub author_prefix: Option<[u8; 4]>,
    /// Text without the NUL terminator.
    pub text: String,
    /// The bytes covered by the ACK hash: `timestamp || flags || text`.
    pub ack_covered: Vec<u8>,
}

/// Parse a decrypted text plaintext (trailing zero padding tolerated).
pub fn parse_text_plain(plain: &[u8]) -> Option<TextPlain> {
    if plain.len() < 5 {
        return None;
    }
    let timestamp = u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]);
    let flags = plain[4];
    let txt_type = flags >> 2;
    let attempt = flags & 3;
    let mut body = &plain[5..];
    let mut author_prefix = None;
    let mut covered_end = 5;
    if txt_type == TXT_TYPE_SIGNED_PLAIN {
        let p = body.get(..4)?;
        author_prefix = Some([p[0], p[1], p[2], p[3]]);
        body = &body[4..];
        covered_end += 4;
    }
    let text_len = body.iter().position(|&b| b == 0).unwrap_or(body.len());
    let text = super::identity::utf8_prefix(&body[..text_len]);
    covered_end += text_len;
    Some(TextPlain { timestamp, txt_type, attempt, author_prefix, text: text.into(), ack_covered: plain[..covered_end].to_vec() })
}

/// Compose a TXT_MSG plaintext (`composeMsgPacket`): the sender includes
/// the terminating NUL. Text above `MAX_TEXT_LEN` is rejected.
pub fn compose_text_plain(timestamp: u32, txt_type: u8, attempt: u8, text: &str) -> Option<Vec<u8>> {
    if text.len() > MAX_TEXT_LEN || text.as_bytes().contains(&0) {
        return None;
    }
    let mut p = Vec::with_capacity(6 + text.len());
    p.extend_from_slice(&timestamp.to_le_bytes());
    p.push(((txt_type & 0x3F) << 2) | (attempt & 3));
    p.extend_from_slice(text.as_bytes());
    p.push(0);
    Some(p)
}

/// Bytes covered by the ACK hash for a composed plaintext (drops the NUL).
pub fn ack_covered(plain_with_nul: &[u8]) -> &[u8] {
    let end = plain_with_nul.get(5..).and_then(|b| b.iter().position(|&x| x == 0)).map(|n| 5 + n).unwrap_or(plain_with_nul.len());
    &plain_with_nul[..end.min(plain_with_nul.len())]
}

/// Build a direct datagram payload (TXT_MSG / REQ / RESPONSE / PATH):
/// `dest_hash || src_hash || MAC || ciphertext`. `None` if it would exceed
/// `MAX_PACKET_PAYLOAD`.
pub fn build_datagram(secret: &Secret, dest_hash: u8, src_hash: u8, plaintext: &[u8]) -> Option<Vec<u8>> {
    if plaintext.len() > crypto::max_plaintext_for(super::packet::MAX_PACKET_PAYLOAD - DATAGRAM_HEADER_LEN) {
        return None;
    }
    let mut out = Vec::with_capacity(DATAGRAM_HEADER_LEN + 2 + plaintext.len() + 16);
    out.push(dest_hash);
    out.push(src_hash);
    out.extend_from_slice(&crypto::encrypt_then_mac(secret, plaintext));
    Some(out)
}

/// Split a direct datagram payload into `(dest_hash, src_hash, MAC||ct)`.
/// The firmware requires `payload_len > 4`.
pub fn split_datagram(payload: &[u8]) -> Option<(u8, u8, &[u8])> {
    if payload.len() <= DATAGRAM_HEADER_LEN {
        return None;
    }
    Some((payload[0], payload[1], &payload[2..]))
}

/// Build a group datagram payload: `channel_hash || MAC || ciphertext`.
pub fn build_group_datagram(secret: &Secret, plaintext: &[u8]) -> Option<Vec<u8>> {
    if plaintext.len() > crypto::max_plaintext_for(super::packet::MAX_PACKET_PAYLOAD - GROUP_HEADER_LEN) {
        return None;
    }
    let mut out = Vec::with_capacity(GROUP_HEADER_LEN + 2 + plaintext.len() + 16);
    out.push(crypto::channel_hash(secret));
    out.extend_from_slice(&crypto::encrypt_then_mac(secret, plaintext));
    Some(out)
}

/// Split a group datagram payload into `(channel_hash, MAC||ct)`.
pub fn split_group_datagram(payload: &[u8]) -> Option<(u8, &[u8])> {
    if payload.len() <= GROUP_HEADER_LEN {
        return None;
    }
    Some((payload[0], &payload[1..]))
}

/// A decoded GRP_TXT plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupText {
    pub timestamp: u32,
    /// Unauthenticated sender name (text before the first `": "`).
    pub sender_name: Option<String>,
    pub text: String,
}

/// Parse a GRP_TXT plaintext. Drops it when `flags >> 2 != 0`
/// (`onGroupDataRecv`).
pub fn parse_group_text(plain: &[u8]) -> Option<GroupText> {
    let t = parse_text_plain(plain)?;
    if t.txt_type != TXT_TYPE_PLAIN {
        return None;
    }
    match t.text.find(": ") {
        Some(i) => Some(GroupText { timestamp: t.timestamp, sender_name: Some(t.text[..i].into()), text: t.text[i + 2..].into() }),
        None => Some(GroupText { timestamp: t.timestamp, sender_name: None, text: t.text }),
    }
}

/// Compose a GRP_TXT plaintext (`sendGroupMessage`): `ts || 0x00 || "name: text"`.
/// The combined `name: text` is capped at `MAX_TEXT_LEN`.
pub fn compose_group_text(timestamp: u32, sender_name: &str, text: &str) -> Option<Vec<u8>> {
    let body_len = sender_name.len() + 2 + text.len();
    if body_len > MAX_TEXT_LEN || sender_name.as_bytes().contains(&0) || text.as_bytes().contains(&0) {
        return None;
    }
    let mut p = Vec::with_capacity(5 + body_len);
    p.extend_from_slice(&timestamp.to_le_bytes());
    p.push(TXT_TYPE_PLAIN);
    p.extend_from_slice(sender_name.as_bytes());
    p.extend_from_slice(b": ");
    p.extend_from_slice(text.as_bytes());
    Some(p)
}

/// A decoded GRP_DATA plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupData {
    pub data_type: u16,
    pub data: Vec<u8>,
}

/// Parse a GRP_DATA plaintext: `data_type u16 LE || len u8 || data`.
pub fn parse_group_data(plain: &[u8]) -> Option<GroupData> {
    if plain.len() < 3 {
        return None;
    }
    let data_type = u16::from_le_bytes([plain[0], plain[1]]);
    let len = plain[2] as usize;
    let data = plain.get(3..3 + len)?;
    Some(GroupData { data_type, data: data.to_vec() })
}

/// Compose a GRP_DATA plaintext (`sendGroupData`).
pub fn compose_group_data(data_type: u16, data: &[u8]) -> Option<Vec<u8>> {
    if data.len() > MAX_GROUP_DATA_LENGTH || data.len() > u8::MAX as usize {
        return None;
    }
    let mut p = Vec::with_capacity(3 + data.len());
    p.extend_from_slice(&data_type.to_le_bytes());
    p.push(data.len() as u8);
    p.extend_from_slice(data);
    Some(p)
}

/// Whether a payload length is a valid ACK (4 or 6 bytes).
pub fn is_ack_len(len: usize) -> bool {
    len == 4 || len == 6
}

/// Whether `s` looks like a chat text (printable / whitespace UTF-8).
pub fn looks_like_text(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t' || c == '\r')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_plain_roundtrip_and_ack_coverage() {
        let p = compose_text_plain(1000, TXT_TYPE_PLAIN, 2, "hi there").unwrap();
        assert_eq!(p.len(), 4 + 1 + 8 + 1);
        assert_eq!(p[4], 2);
        assert_eq!(*p.last().unwrap(), 0);
        let t = parse_text_plain(&p).unwrap();
        assert_eq!(t.text, "hi there");
        assert_eq!(t.attempt, 2);
        assert_eq!(t.txt_type, 0);
        assert_eq!(t.ack_covered, &p[..13]);
        assert_eq!(ack_covered(&p), &p[..13]);
        // padded like a decrypted block
        let mut padded = p.clone();
        padded.resize(32, 0);
        assert_eq!(parse_text_plain(&padded).unwrap(), t);
        assert!(compose_text_plain(0, 0, 0, &"x".repeat(161)).is_none());
        assert!(parse_text_plain(&[1, 2, 3]).is_none());
        // signed plain
        let mut s = compose_text_plain(5, TXT_TYPE_SIGNED_PLAIN, 1, "zzzzpost").unwrap();
        s[5..9].copy_from_slice(&[9, 8, 7, 6]);
        let t = parse_text_plain(&s).unwrap();
        assert_eq!(t.author_prefix, Some([9, 8, 7, 6]));
        assert_eq!(t.text, "post");
        assert_eq!(t.ack_covered.len(), 9 + 4);
    }

    #[test]
    fn group_text_roundtrip() {
        let p = compose_group_text(77, "Bob", "hello: world").unwrap();
        assert_eq!(&p[..4], &77u32.to_le_bytes());
        assert_eq!(p[4], 0);
        assert_eq!(&p[5..], b"Bob: hello: world");
        let g = parse_group_text(&p).unwrap();
        assert_eq!(g.sender_name.as_deref(), Some("Bob"));
        assert_eq!(g.text, "hello: world");
        let mut cli = p.clone();
        cli[4] = 1 << 2;
        assert!(parse_group_text(&cli).is_none());
        let noname = [0, 0, 0, 0, 0, b'x', b'y'];
        let g = parse_group_text(&noname).unwrap();
        assert_eq!(g.sender_name, None);
        assert_eq!(g.text, "xy");
        assert!(compose_group_text(0, "n", &"x".repeat(158)).is_none());
        assert!(compose_group_text(0, "n", &"x".repeat(157)).is_some());
    }

    #[test]
    fn group_data_roundtrip_and_datagrams() {
        let p = compose_group_data(0xFF01, b"\x01\x02").unwrap();
        assert_eq!(p, alloc::vec![0x01, 0xFF, 2, 1, 2]);
        assert_eq!(parse_group_data(&p).unwrap(), GroupData { data_type: 0xFF01, data: alloc::vec![1, 2] });
        assert!(parse_group_data(&[1, 0, 5, 1]).is_none());
        assert!(compose_group_data(0, &[0; 166]).is_none());
        let s = [3u8; 32];
        let d = build_datagram(&s, 0xAA, 0xBB, b"plain").unwrap();
        assert_eq!(d.len(), 4 + 16);
        let (dh, sh, blob) = split_datagram(&d).unwrap();
        assert_eq!((dh, sh), (0xAA, 0xBB));
        assert_eq!(&crypto::mac_then_decrypt(&s, blob).unwrap()[..5], b"plain");
        assert!(build_datagram(&s, 0, 0, &[0; 177]).is_none());
        assert!(build_datagram(&s, 0, 0, &[0; 176]).is_some());
        let g = build_group_datagram(&s, b"x").unwrap();
        assert_eq!(g.len(), 3 + 16);
        assert_eq!(g[0], crypto::channel_hash(&s));
        assert!(split_datagram(&[1, 2, 3, 4]).is_none());
        assert!(split_group_datagram(&[1, 2, 3]).is_none());
        assert!(is_ack_len(4) && is_ack_len(6) && !is_ack_len(5));
        assert!(looks_like_text("hi\n"));
        assert!(!looks_like_text("a\u{1}b"));
        assert!(!looks_like_text(""));
    }
}
