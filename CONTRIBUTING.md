# Contributing to MeshStar

Thanks for wanting to help. MeshStar is a LoRa mesh protocol that carries
private messages over a public band, so the bar for correctness and honesty is
high. These rules keep it that way.

## Ground rules

- **Read `docs/STATUS.md` first.** It has the real state, the closed design
  decisions and the pending plan. Do not reopen a closed decision without data
  from the simulator.
- **The core is `#![no_std]` + `alloc` and `#![forbid(unsafe_code)]`.** It does
  no I/O: the `Node` engine takes frames and time, and returns frames and
  events. Never put Meshtastic or MeshCore logic into `meshstar-core`.
- **Never trust bytes from the air.** All validation lives in `Packet::decode`
  and in each codec's `decode`, which return `Err` and never panic. Every new
  codec ships with a "random garbage does not panic" test, and ideally a fuzz
  target in `crates/meshstar-core/fuzz`.
- **Real cryptography only**, from audited crates (`ed25519-dalek`,
  `x25519-dalek`, `chacha20poly1305`, `sha2`, `hmac`, `aes`, `ctr`, `ccm`).
  Noise is implemented to spec in `crypto/noise.rs`; do not change primitives
  without updating `PROTOCOL_NAME_*`.
- **Foreign adapters use only verified facts** from `docs/research/*`. Anything
  unverified is marked `// UNVERIFIED:` and called out in the module's
  "Fidelity" section. Do not invent capabilities.
- **Every bounded structure** (caches, queues, mailbox, reassembly) has a
  configurable limit and an exhaustion test.
- **Language:** code, comments and technical docs in English.

## Before you open a pull request

Run the same checks CI runs:

```
cargo test --workspace                               # all tests
cargo clippy --workspace --all-targets               # must be clean
cargo build -p meshstar-core --no-default-features   # no_std still builds
cargo fmt                                            # long lines are allowed; match existing style
```

If you touched a decoder, also run its fuzz target for a while:

```
cd crates/meshstar-core
cargo +nightly fuzz run <target> -- -max_total_time=120
```

If you changed protocol behaviour, back it with the simulator and, where it
matters, update `docs/BENCHMARKS.md` with reproducible numbers:

```
target/release/meshstar sim ...        # see docs/SIMULATOR.md
benchmarks/run.sh                      # reproduces BENCHMARKS.md
```

## Pull request checklist

- [ ] Tests pass and clippy is clean.
- [ ] New decoders have a garbage-does-not-panic test (and a fuzz target).
- [ ] New bounded structures have an exhaustion test.
- [ ] Protocol changes are justified with simulator data.
- [ ] Docs updated (module doc-comments, and `docs/` where relevant).
- [ ] Commit messages explain the why, not just the what.

## Reporting bugs and asking for features

Use the issue templates. For security issues, follow `SECURITY.md` and report
privately first.

## License

By contributing, you agree your contribution is licensed under GPL-3.0, the
same license as the project.
