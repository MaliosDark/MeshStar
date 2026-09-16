//! Minimal, audited-by-construction implementation of the Noise Protocol
//! Framework primitives needed by MeshStar (revision 34 semantics).
//!
//! Patterns:
//!
//! ```text
//! XX:
//!   -> e
//!   <- e, ee, s, es
//!   -> s, se
//!
//! X:
//!   <- s          (pre-message: recipient static known from a beacon,
//!                  an anchor directory reply or a previous session)
//!   ...
//!   -> e, es, s, ss
//! ```

use alloc::vec::Vec;

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::identity::{Identity, PublicIdentity};
use crate::protocol::{Error, Result, TAG_LEN};

pub const PROTOCOL_NAME_XX: &[u8] = b"Noise_XX_25519_ChaChaPoly_SHA256";
pub const PROTOCOL_NAME_X: &[u8] = b"Noise_X_25519_ChaChaPoly_SHA256";
pub const DH_LEN: usize = 32;

/// Noise `CipherState`: key + nonce counter.
#[derive(Clone)]
pub struct CipherState {
    k: Option<[u8; 32]>,
    n: u64,
}

impl core::fmt::Debug for CipherState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CipherState(n={})", self.n)
    }
}

impl CipherState {
    pub fn empty() -> Self {
        Self { k: None, n: 0 }
    }
    pub fn with_key(k: [u8; 32]) -> Self {
        Self { k: Some(k), n: 0 }
    }
    pub fn has_key(&self) -> bool {
        self.k.is_some()
    }
    pub fn nonce(&self) -> u64 {
        self.n
    }
    pub fn set_nonce(&mut self, n: u64) {
        self.n = n;
    }

    fn nonce_bytes(n: u64) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[4..].copy_from_slice(&n.to_le_bytes());
        b
    }

    /// Encrypt with the current nonce, then increment.
    pub fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        match self.k {
            None => plaintext.to_vec(),
            Some(k) => {
                let out = Self::encrypt_n(&k, self.n, ad, plaintext);
                self.n = self.n.wrapping_add(1);
                out
            }
        }
    }

    /// Decrypt with the current nonce, then increment.
    pub fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        match self.k {
            None => Ok(ciphertext.to_vec()),
            Some(k) => {
                let out = Self::decrypt_n(&k, self.n, ad, ciphertext)?;
                self.n = self.n.wrapping_add(1);
                Ok(out)
            }
        }
    }

    /// Encrypt with an explicit nonce (transport messages carry it).
    pub fn encrypt_n(k: &[u8; 32], n: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(k.into());
        let mut buf = plaintext.to_vec();
        let tag = cipher.encrypt_in_place_detached(&Self::nonce_bytes(n).into(), ad, &mut buf).expect("in place");
        buf.extend_from_slice(&tag);
        buf
    }

    pub fn decrypt_n(k: &[u8; 32], n: u64, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < TAG_LEN {
            return Err(Error::Truncated);
        }
        let cipher = ChaCha20Poly1305::new(k.into());
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
        let mut buf = ct.to_vec();
        cipher
            .decrypt_in_place_detached(&Self::nonce_bytes(n).into(), ad, &mut buf, tag.into())
            .map_err(|_| Error::AuthFailed)?;
        Ok(buf)
    }

    pub fn key(&self) -> Option<&[u8; 32]> {
        self.k.as_ref()
    }
}

fn hmac(key: &[u8], data: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    for d in data {
        m.update(d);
    }
    m.finalize().into_bytes().into()
}

/// Noise HKDF (HMAC based, 2 outputs).
pub fn hkdf2(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp = hmac(ck, &[ikm]);
    let o1 = hmac(&temp, &[&[1u8]]);
    let o2 = hmac(&temp, &[&o1, &[2u8]]);
    (o1, o2)
}

/// Noise `SymmetricState`.
#[derive(Clone)]
pub struct SymmetricState {
    cs: CipherState,
    ck: [u8; 32],
    h: [u8; 32],
}

impl core::fmt::Debug for SymmetricState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SymmetricState")
    }
}

impl SymmetricState {
    pub fn new(protocol_name: &[u8]) -> Self {
        let h: [u8; 32] = if protocol_name.len() <= 32 {
            let mut h = [0u8; 32];
            h[..protocol_name.len()].copy_from_slice(protocol_name);
            h
        } else {
            Sha256::digest(protocol_name).into()
        };
        Self { cs: CipherState::empty(), ck: h, h }
    }

    pub fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = hkdf2(&self.ck, ikm);
        self.ck = ck;
        self.cs = CipherState::with_key(k);
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut d = Sha256::new();
        d.update(self.h);
        d.update(data);
        self.h = d.finalize().into();
    }

    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let ct = self.cs.encrypt_with_ad(&self.h, plaintext);
        self.mix_hash(&ct);
        ct
    }

    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let pt = self.cs.decrypt_with_ad(&self.h, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    pub fn split(&self) -> (CipherState, CipherState) {
        let (k1, k2) = hkdf2(&self.ck, &[]);
        (CipherState::with_key(k1), CipherState::with_key(k2))
    }

    pub fn handshake_hash(&self) -> [u8; 32] {
        self.h
    }

    pub fn has_key(&self) -> bool {
        self.cs.has_key()
    }
}

/// Which side of the handshake we are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoiseRole {
    Initiator,
    Responder,
}

/// Keys produced by `Split()`, oriented from our point of view.
#[derive(Clone)]
pub struct TransportKeys {
    pub send: [u8; 32],
    pub recv: [u8; 32],
    pub handshake_hash: [u8; 32],
}

impl core::fmt::Debug for TransportKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TransportKeys(..)")
    }
}

/// Which message of the XX pattern a buffer contains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeMessage {
    One = 1,
    Two = 2,
    Three = 3,
}

impl HandshakeMessage {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::One),
            2 => Some(Self::Two),
            3 => Some(Self::Three),
            _ => None,
        }
    }
}

fn dh(secret: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32]> {
    let s = StaticSecret::from(*secret);
    let shared = s.diffie_hellman(&PublicKey::from(*public));
    // Reject low order points (contributory behaviour).
    if !shared.was_contributory() {
        return Err(Error::AuthFailed);
    }
    Ok(*shared.as_bytes())
}

/// Noise XX handshake state machine.
///
/// ```text
/// initiator                         responder
///   write_message_1()  ----------->  read_message_1()
///   read_message_2()   <-----------  write_message_2()
///   write_message_3()  ----------->  read_message_3()
///   finish()                         finish()
/// ```
///
/// Handshake payloads carry the Ed25519 public key of the sender; the
/// reader checks that it maps to the received Noise static key and returns
/// the verified [`PublicIdentity`].
pub struct HandshakeXX {
    role: NoiseRole,
    ss: SymmetricState,
    s: [u8; 32],
    s_pub: [u8; 32],
    ed_pub: [u8; 32],
    e: Option<[u8; 32]>,
    e_pub: [u8; 32],
    re: Option<[u8; 32]>,
    rs: Option<[u8; 32]>,
    step: u8,
    remote: Option<PublicIdentity>,
}

impl core::fmt::Debug for HandshakeXX {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HandshakeXX({:?}, step {})", self.role, self.step)
    }
}

impl HandshakeXX {
    /// `prologue` must be identical on both sides (MeshStar binds the
    /// initiator and responder addresses into it).
    pub fn new<R: rand_core::RngCore + rand_core::CryptoRng>(role: NoiseRole, identity: &Identity, prologue: &[u8], rng: &mut R) -> Self {
        let mut ss = SymmetricState::new(PROTOCOL_NAME_XX);
        ss.mix_hash(prologue);
        let mut e = [0u8; 32];
        rng.fill_bytes(&mut e);
        let e_pub = *PublicKey::from(&StaticSecret::from(e)).as_bytes();
        Self {
            role,
            ss,
            s: *identity.noise_static_secret(),
            s_pub: *identity.public().noise_static_public(),
            ed_pub: identity.public().public_key_bytes(),
            e: Some(e),
            e_pub,
            re: None,
            rs: None,
            step: 0,
            remote: None,
        }
    }

    pub fn role(&self) -> NoiseRole {
        self.role
    }

    /// Verified identity of the peer, available after message 2 (initiator)
    /// or message 3 (responder).
    pub fn remote_identity(&self) -> Option<&PublicIdentity> {
        self.remote.as_ref()
    }

    fn identity_payload(&self, extra: &[u8]) -> Vec<u8> {
        let mut p = Vec::with_capacity(32 + extra.len());
        p.extend_from_slice(&self.ed_pub);
        p.extend_from_slice(extra);
        p
    }

    /// Parse an identity payload and verify the binding to `rs`.
    fn verify_identity_payload(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() < 32 {
            return Err(Error::Truncated);
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&payload[..32]);
        let id = PublicIdentity::from_bytes(&pk)?;
        let rs = self.rs.ok_or(Error::HandshakeState)?;
        if id.noise_static_public() != &rs {
            return Err(Error::AuthFailed);
        }
        self.remote = Some(id);
        Ok(payload[32..].to_vec())
    }

    // -> e
    pub fn write_message_1(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if self.role != NoiseRole::Initiator || self.step != 0 {
            return Err(Error::HandshakeState);
        }
        let mut out = Vec::with_capacity(32 + payload.len());
        out.extend_from_slice(&self.e_pub);
        self.ss.mix_hash(&self.e_pub);
        out.extend_from_slice(&self.ss.encrypt_and_hash(payload));
        self.step = 1;
        Ok(out)
    }

    pub fn read_message_1(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        if self.role != NoiseRole::Responder || self.step != 0 {
            return Err(Error::HandshakeState);
        }
        if msg.len() < 32 {
            return Err(Error::Truncated);
        }
        let mut re = [0u8; 32];
        re.copy_from_slice(&msg[..32]);
        self.re = Some(re);
        self.ss.mix_hash(&re);
        let payload = self.ss.decrypt_and_hash(&msg[32..])?;
        self.step = 1;
        Ok(payload)
    }

    // <- e, ee, s, es
    pub fn write_message_2(&mut self, extra: &[u8]) -> Result<Vec<u8>> {
        if self.role != NoiseRole::Responder || self.step != 1 {
            return Err(Error::HandshakeState);
        }
        let re = self.re.ok_or(Error::HandshakeState)?;
        let e = self.e.ok_or(Error::HandshakeState)?;
        let mut out = Vec::with_capacity(32 + 48 + 32 + 16 + extra.len());
        out.extend_from_slice(&self.e_pub);
        self.ss.mix_hash(&self.e_pub);
        self.ss.mix_key(&dh(&e, &re)?); // ee
        out.extend_from_slice(&self.ss.encrypt_and_hash(&self.s_pub)); // s
        self.ss.mix_key(&dh(&self.s, &re)?); // es (responder: DH(s, re))
        let payload = self.identity_payload(extra);
        out.extend_from_slice(&self.ss.encrypt_and_hash(&payload));
        self.step = 2;
        Ok(out)
    }

    pub fn read_message_2(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        if self.role != NoiseRole::Initiator || self.step != 1 {
            return Err(Error::HandshakeState);
        }
        if msg.len() < 32 + 48 + 16 {
            return Err(Error::Truncated);
        }
        let e = self.e.ok_or(Error::HandshakeState)?;
        let mut re = [0u8; 32];
        re.copy_from_slice(&msg[..32]);
        self.re = Some(re);
        self.ss.mix_hash(&re);
        self.ss.mix_key(&dh(&e, &re)?); // ee
        let rs_bytes = self.ss.decrypt_and_hash(&msg[32..80])?;
        let mut rs = [0u8; 32];
        rs.copy_from_slice(&rs_bytes);
        self.rs = Some(rs);
        self.ss.mix_key(&dh(&e, &rs)?); // es (initiator: DH(e, rs))
        let payload = self.ss.decrypt_and_hash(&msg[80..])?;
        let extra = self.verify_identity_payload(&payload)?;
        self.step = 2;
        Ok(extra)
    }

    // -> s, se
    pub fn write_message_3(&mut self, extra: &[u8]) -> Result<Vec<u8>> {
        if self.role != NoiseRole::Initiator || self.step != 2 {
            return Err(Error::HandshakeState);
        }
        let re = self.re.ok_or(Error::HandshakeState)?;
        let mut out = Vec::with_capacity(48 + 32 + 16 + extra.len());
        out.extend_from_slice(&self.ss.encrypt_and_hash(&self.s_pub)); // s
        self.ss.mix_key(&dh(&self.s, &re)?); // se (initiator: DH(s, re))
        let payload = self.identity_payload(extra);
        out.extend_from_slice(&self.ss.encrypt_and_hash(&payload));
        self.step = 3;
        Ok(out)
    }

    pub fn read_message_3(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        if self.role != NoiseRole::Responder || self.step != 2 {
            return Err(Error::HandshakeState);
        }
        if msg.len() < 48 + 16 {
            return Err(Error::Truncated);
        }
        let e = self.e.ok_or(Error::HandshakeState)?;
        let rs_bytes = self.ss.decrypt_and_hash(&msg[..48])?;
        let mut rs = [0u8; 32];
        rs.copy_from_slice(&rs_bytes);
        self.rs = Some(rs);
        self.ss.mix_key(&dh(&e, &rs)?); // se (responder: DH(e, rs))
        let payload = self.ss.decrypt_and_hash(&msg[48..])?;
        let extra = self.verify_identity_payload(&payload)?;
        self.step = 3;
        Ok(extra)
    }

    /// Split into transport keys. Consumes the ephemeral secret.
    pub fn finish(mut self) -> Result<(TransportKeys, PublicIdentity)> {
        if self.step != 3 {
            return Err(Error::HandshakeState);
        }
        let (c1, c2) = self.ss.split();
        let (send, recv) = match self.role {
            NoiseRole::Initiator => (c1, c2),
            NoiseRole::Responder => (c2, c1),
        };
        self.e = None;
        let remote = self.remote.take().ok_or(Error::HandshakeState)?;
        Ok((
            TransportKeys { send: *send.key().unwrap(), recv: *recv.key().unwrap(), handshake_hash: self.ss.handshake_hash() },
            remote,
        ))
    }
}

/// Noise X one-way message: `-> e, es, s, ss` with the recipient static
/// as pre-message. Returns the message; the payload is authenticated and
/// encrypted to the recipient and the sender is authenticated to the
/// recipient (identity payload prefix, verified on open).
pub fn x_seal<R: rand_core::RngCore + rand_core::CryptoRng>(sender: &Identity, recipient: &PublicIdentity, prologue: &[u8], payload: &[u8], rng: &mut R) -> Result<Vec<u8>> {
    let mut ss = SymmetricState::new(PROTOCOL_NAME_X);
    ss.mix_hash(prologue);
    let rs = *recipient.noise_static_public();
    ss.mix_hash(&rs); // pre-message <- s
    let mut e = [0u8; 32];
    rng.fill_bytes(&mut e);
    let e_pub = *PublicKey::from(&StaticSecret::from(e)).as_bytes();
    let mut out = Vec::with_capacity(32 + 48 + 32 + payload.len() + 16);
    out.extend_from_slice(&e_pub);
    ss.mix_hash(&e_pub);
    ss.mix_key(&dh(&e, &rs)?); // es
    out.extend_from_slice(&ss.encrypt_and_hash(sender.public().noise_static_public())); // s
    ss.mix_key(&dh(sender.noise_static_secret(), &rs)?); // ss
    let mut body = Vec::with_capacity(32 + payload.len());
    body.extend_from_slice(&sender.public().public_key_bytes());
    body.extend_from_slice(payload);
    out.extend_from_slice(&ss.encrypt_and_hash(&body));
    Ok(out)
}

/// Open a Noise X message. Returns the verified sender identity and payload.
pub fn x_open(recipient: &Identity, prologue: &[u8], msg: &[u8]) -> Result<(PublicIdentity, Vec<u8>)> {
    if msg.len() < 32 + 48 + 32 + 16 {
        return Err(Error::Truncated);
    }
    let mut ss = SymmetricState::new(PROTOCOL_NAME_X);
    ss.mix_hash(prologue);
    ss.mix_hash(recipient.public().noise_static_public());
    let mut re = [0u8; 32];
    re.copy_from_slice(&msg[..32]);
    ss.mix_hash(&re);
    ss.mix_key(&dh(recipient.noise_static_secret(), &re)?); // es
    let rs_bytes = ss.decrypt_and_hash(&msg[32..80])?;
    let mut rs = [0u8; 32];
    rs.copy_from_slice(&rs_bytes);
    ss.mix_key(&dh(recipient.noise_static_secret(), &rs)?); // ss
    let body = ss.decrypt_and_hash(&msg[80..])?;
    if body.len() < 32 {
        return Err(Error::Truncated);
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&body[..32]);
    let sender = PublicIdentity::from_bytes(&pk)?;
    if sender.noise_static_public() != &rs {
        return Err(Error::AuthFailed);
    }
    Ok((sender, body[32..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn pair() -> (Identity, Identity, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let a = Identity::generate(&mut rng);
        let b = Identity::generate(&mut rng);
        (a, b, rng)
    }

    #[test]
    fn xx_full_handshake() {
        let (a, b, mut rng) = pair();
        let prologue = b"test";
        let mut hi = HandshakeXX::new(NoiseRole::Initiator, &a, prologue, &mut rng);
        let mut hr = HandshakeXX::new(NoiseRole::Responder, &b, prologue, &mut rng);
        let m1 = hi.write_message_1(b"p1").unwrap();
        assert_eq!(hr.read_message_1(&m1).unwrap(), b"p1");
        let m2 = hr.write_message_2(b"p2").unwrap();
        assert_eq!(hi.read_message_2(&m2).unwrap(), b"p2");
        assert_eq!(hi.remote_identity().unwrap().address(), b.address());
        let m3 = hi.write_message_3(b"p3").unwrap();
        assert_eq!(hr.read_message_3(&m3).unwrap(), b"p3");
        let (ki, idb) = hi.finish().unwrap();
        let (kr, ida) = hr.finish().unwrap();
        assert_eq!(idb.address(), b.address());
        assert_eq!(ida.address(), a.address());
        assert_eq!(ki.send, kr.recv);
        assert_eq!(ki.recv, kr.send);
        assert_ne!(ki.send, ki.recv);
        assert_eq!(ki.handshake_hash, kr.handshake_hash);
        // sizes
        assert_eq!(m1.len(), 32 + 2);
        assert_eq!(m2.len(), 32 + 48 + 32 + 2 + 16);
        assert_eq!(m3.len(), 48 + 32 + 2 + 16);
    }

    #[test]
    fn xx_prologue_mismatch_fails() {
        let (a, b, mut rng) = pair();
        let mut hi = HandshakeXX::new(NoiseRole::Initiator, &a, b"x", &mut rng);
        let mut hr = HandshakeXX::new(NoiseRole::Responder, &b, b"y", &mut rng);
        let m1 = hi.write_message_1(b"").unwrap();
        hr.read_message_1(&m1).unwrap();
        let m2 = hr.write_message_2(b"").unwrap();
        assert!(hi.read_message_2(&m2).is_err());
    }

    #[test]
    fn xx_wrong_identity_is_detected() {
        // Responder claims an Ed25519 key that does not map to its static.
        let (a, b, mut rng) = pair();
        let c = Identity::generate(&mut rng);
        let mut hi = HandshakeXX::new(NoiseRole::Initiator, &a, b"p", &mut rng);
        let mut hr = HandshakeXX::new(NoiseRole::Responder, &b, b"p", &mut rng);
        hr.ed_pub = c.public().public_key_bytes();
        let m1 = hi.write_message_1(b"").unwrap();
        hr.read_message_1(&m1).unwrap();
        let m2 = hr.write_message_2(b"").unwrap();
        assert_eq!(hi.read_message_2(&m2), Err(Error::AuthFailed));
    }

    #[test]
    fn xx_state_machine_enforced() {
        let (a, _b, mut rng) = pair();
        let mut hi = HandshakeXX::new(NoiseRole::Initiator, &a, b"p", &mut rng);
        assert_eq!(hi.write_message_3(b""), Err(Error::HandshakeState));
        assert_eq!(hi.read_message_1(b""), Err(Error::HandshakeState));
        let _ = hi.write_message_1(b"").unwrap();
        assert_eq!(hi.write_message_1(b""), Err(Error::HandshakeState));
        assert!(hi.finish().is_err());
    }

    #[test]
    fn xx_corrupted_message_rejected() {
        let (a, b, mut rng) = pair();
        let mut hi = HandshakeXX::new(NoiseRole::Initiator, &a, b"p", &mut rng);
        let mut hr = HandshakeXX::new(NoiseRole::Responder, &b, b"p", &mut rng);
        let m1 = hi.write_message_1(b"").unwrap();
        hr.read_message_1(&m1).unwrap();
        let mut m2 = hr.write_message_2(b"").unwrap();
        m2[40] ^= 0x55;
        assert_eq!(hi.read_message_2(&m2), Err(Error::AuthFailed));
    }

    #[test]
    fn x_seal_open() {
        let (a, b, mut rng) = pair();
        let msg = x_seal(&a, b.public(), b"pro", b"offline hello", &mut rng).unwrap();
        let (sender, pt) = x_open(&b, b"pro", &msg).unwrap();
        assert_eq!(sender.address(), a.address());
        assert_eq!(pt, b"offline hello");
        assert!(x_open(&a, b"pro", &msg).is_err()); // wrong recipient
        assert!(x_open(&b, b"prx", &msg).is_err()); // wrong prologue
        let mut bad = msg.clone();
        let l = bad.len();
        bad[l - 1] ^= 1;
        assert!(x_open(&b, b"pro", &bad).is_err());
    }

    #[test]
    fn low_order_point_rejected() {
        assert_eq!(dh(&[1u8; 32], &[0u8; 32]), Err(Error::AuthFailed));
    }
}
