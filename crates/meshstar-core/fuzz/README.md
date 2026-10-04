# Fuzzing MeshStar decoders

Every byte that reaches MeshStar from the air or over BLE is untrusted, so each
decoder must return `Err` on garbage and never panic. These fuzz targets drive
that invariant continuously with libFuzzer (via `cargo-fuzz`).

## Targets

| Target | Covers |
|---|---|
| `core_packet` | `Packet::decode`, the main on-air frame decoder |
| `core_zrp` | `RouteRequest` / `RouteReply` / `RouteError` decoders |
| `core_neighbor` | `Beacon::decode`, the most frequent frame in a dense mesh |
| `core_transport` | `Ack` and store-and-forward `StoreRequest` decoders |
| `proto_meshtastic` | Meshtastic header and protobuf payload decoders |
| `proto_meshcore` | MeshCore packet framing and identity advert decoders |
| `companion` | companion BLE protocol and the thumbnail image codec |

## Run

Needs a nightly toolchain and `cargo-fuzz` (`cargo install cargo-fuzz`).

```
rustup toolchain install nightly
cd crates/meshstar-core

# run one target until you stop it
cargo +nightly fuzz run core_packet

# a bounded run (used by CI)
cargo +nightly fuzz run core_packet -- -max_total_time=60

# list every target
cargo +nightly fuzz list
```

A crash drops a reproducer in `fuzz/artifacts/<target>/`; replay it with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>`.

The generated `corpus/`, `artifacts/` and `coverage/` directories are not
committed; the targets and `Cargo.lock` are.
