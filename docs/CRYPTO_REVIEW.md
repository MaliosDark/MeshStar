# Cryptography review guide

This document is for anyone reviewing or auditing MeshStar's cryptography. It
states exactly what is standard, what is MeshStar-specific, where the code is,
and how it is tested, so a reviewer can go straight to what matters.

MeshStar carries private messages over a public radio band, so the handshake
and transport crypto are the most security-critical code in the project. The
only hand-written piece is the Noise state machine; every primitive comes from
an audited crate.

## Suite and primitives

- Handshake: **Noise XX**, protocol name `Noise_XX_25519_ChaChaPoly_SHA256`.
- One-shot offline messages: **Noise X**, `Noise_X_25519_ChaChaPoly_SHA256`.
- Signatures and identity: **Ed25519** (`ed25519-dalek`).
- Key agreement: **X25519** (`x25519-dalek`).
- AEAD: **ChaCha20-Poly1305** (`chacha20poly1305`).
- Hash and KDF: **SHA-256** with **HMAC** (`sha2`, `hmac`).
- Meshtastic / MeshCore interop uses `aes`, `ctr`, `ccm` in the adapters only,
  never for MeshStar's own traffic.

The protocol names are pinned as `PROTOCOL_NAME_XX` / `PROTOCOL_NAME_X` in
`crates/meshstar-core/src/crypto/noise.rs`; the primitives must not change
without changing those names.

## What is standard Noise XX

The handshake in `noise.rs` follows the Noise XX pattern exactly:

```
-> e
<- e, ee, s, es
-> s, se
```

`write_message_1/2/3` and `read_message_1/2/3` implement those tokens with the
standard `MixKey` / `MixHash` / `EncryptAndHash` operations on a
`SymmetricState`, the standard two-output Noise `HKDF`, and `Split` into two
`CipherState` transport keys. Nonces are the Noise layout: a 12-byte nonce of
four zero bytes followed by the 64-bit counter in little-endian.

## What is MeshStar-specific (and why)

1. **Identity binding in the handshake payload.** The X25519 static key used in
   the DH is derived from the node's Ed25519 identity by the standard
   birational map (public key via `to_montgomery`, secret via
   `SHA-512(seed)[0..32]` clamped; see `identity/mod.rs`, with a consistency
   test). The handshake payload carries the node's Ed25519 public key, and
   `verify_identity_payload` checks that the peer's advertised Ed25519 key maps
   to the X25519 static key actually used in the handshake. This binds the
   signing identity to the key-exchange identity; a mismatch is `AuthFailed`.
   It is an addition on top of standard XX, not a change to the key schedule.
2. **Prologue binds the endpoints.** The initiator and responder addresses are
   mixed into the prologue, so a handshake transcript is bound to the pair it
   was meant for.
3. **Piggybacking.** The routing layer can carry Noise message 1 inside a route
   request and message 2 inside the reply; this is transport framing only and
   does not alter the handshake bytes.

Because the payload format is fixed (Ed25519 key first), the full handshake
does not match generic Noise XX test vectors byte for byte. The underlying key
schedule, DH and AEAD are standard and are checked separately (below).

## Where the code is

- `crates/meshstar-core/src/crypto/noise.rs`: `CipherState`, `SymmetricState`,
  `hkdf2`, `HandshakeXX`, Noise X helpers, transport key derivation.
- `crates/meshstar-core/src/identity/mod.rs`: Ed25519 identity and the
  Ed25519 to X25519 static derivation.
- `crates/meshstar-core/src/packet/mod.rs`: how sealed frames are framed and
  decoded (the untrusted entry point).

## Test coverage

In `noise.rs` unit tests:

- `hkdf2_known_answer_vectors`: the hand-written Noise HKDF against known
  answers computed by an independent reference (Python `hmac`/`hashlib`).
- `xx_full_handshake`: both sides derive identical transport keys and handshake
  hash, send and receive keys are mirrored and distinct, and message sizes are
  exact.
- Tamper and authentication: a flipped byte in message 2 fails; a wrong
  identity binding returns `AuthFailed`; a wrong prologue fails Noise X.
- State machine: out-of-order calls return `HandshakeState`.
- `dh` rejects a low-order / all-zero output.

Project-wide:

- Continuous fuzzing of every decoder, including the sealed-frame path
  (`crates/meshstar-core/fuzz`), in CI and nightly.
- The rule that `decode` never panics on hostile input, with a
  garbage-does-not-panic test per codec.

## What a reviewer should check

1. The XX token sequence and the `ee` / `es` / `se` DH directions in
   `write_message_2/3` and `read_message_2/3` match the Noise specification.
2. The identity binding in `verify_identity_payload` cannot be bypassed and
   actually ties the Ed25519 key to the DH static key.
3. The Ed25519 to X25519 derivation in `identity/mod.rs` is the standard map and
   does not weaken the key.
4. Nonce handling: the counter never repeats under a key, and rekey / session
   limits in the session layer are enforced.
5. Transport `Split` labels and the `CipherState` nonce layout.
6. No secret-dependent branching or timing that a constant-time primitive would
   otherwise avoid (the primitives themselves are from vetted crates).

## Known limitations and non-goals

- MeshStar does not implement post-quantum key exchange.
- Metadata (who is talking to whom, and that a message exists) is visible to
  relays by design; only content is protected.
- Foreign networks (Meshtastic, MeshCore) use shared channel keys; MeshStar
  never presents those as end-to-end encryption and labels them honestly.

## Reporting

Security issues go through `SECURITY.md` (private advisory first), not public
issues.
