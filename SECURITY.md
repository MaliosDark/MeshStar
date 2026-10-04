# Security policy

MeshStar is a security-focused project: it carries people's private messages
over a public radio band. We take reports seriously and we design to make them
rare.

## Reporting a vulnerability

Please report security issues privately first, not in a public issue:

- Open a private advisory on GitHub (Security tab, "Report a vulnerability"), or
- Email the maintainer listed on the GitHub profile.

Include what you found, how to reproduce it, and the impact you see. We aim to
acknowledge within a few days and to agree a disclosure timeline with you. We
credit reporters who want it.

## What we already do

- **Every byte from the air or BLE is untrusted.** Validation lives in
  `Packet::decode` and in each codec's `decode`, which return `Err` and never
  panic. Each new codec ships with a "random garbage does not panic" test.
- **Continuous fuzzing.** The decoders are fuzzed with libFuzzer
  (see `crates/meshstar-core/fuzz/`): a short smoke run on every CI build and a
  longer scheduled run nightly. Reproducers from any crash are uploaded as
  artifacts.
- **Audited cryptography primitives.** Signatures, key exchange and AEAD use
  vetted crates (`ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `sha2`,
  `hmac`, `aes`, `ctr`, `ccm`). The Noise XX state machine is implemented to the
  specification in `crypto/noise.rs`; its primitives are pinned by
  `PROTOCOL_NAME_*` and are not changed without updating those.
- **End-to-end by default.** MeshStar unicast runs inside Noise XX sessions with
  mutual authentication and forward secrecy. Relays forward but cannot read.
- **Honest labelling.** Foreign networks (Meshtastic, MeshCore) use shared
  channel keys. MeshStar never presents a channel key as end-to-end encryption;
  each message carries its real security level.

See `docs/THREAT_MODEL.md` for the full model and its assumptions.

## Scope

In scope: the protocol, the decoders, the cryptography, the companion protocol,
and the firmware. Out of scope: physical attacks on a device you hand to someone,
and the inherent fact that LoRa transmissions are detectable by radio.

## Supported versions

MeshStar is pre-1.0 and moves fast. Security fixes land on `main`; please test
against `main` before reporting.
