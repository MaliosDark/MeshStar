# MeshStar, guía para trabajar en este repositorio

MeshStar es una plataforma LoRa mesh de nueva generación (Rust, GPL-3.0) con protocolo
propio (ZRP + Noise XX + Ed25519 + LEAF/ANCHOR + store-and-forward + protección contra
tormentas) y una capa de interoperabilidad con Meshtastic y MeshCore mediante adaptadores.

**Antes de nada lee `docs/STATUS.md`**: contiene el estado real, las decisiones de diseño
cerradas y el plan detallado de lo pendiente. No reabras decisiones ya tomadas sin motivo.

## Estructura
```
crates/meshstar-core        núcleo no_std (identity, packet, crypto, fragmentation, neighbor,
                            routing, zrp, storm, transport, store_forward, power, radio,
                            platform, node)   ← fuente de verdad del protocolo (doc-comments //!)
crates/meshstar-protocols   adaptadores: model, adapter (trait RadioProtocol), profiles,
                            meshstar/, meshtastic/, meshcore/, detector/, bridge/
crates/meshstar-sim         simulador (pendiente)
crates/meshstar-cli         binario `meshstar` (pendiente)
crates/meshstar-radio-*     drivers SX126x / SX127x sobre embedded-hal (pendiente)
examples/esp32-*            firmware de ejemplo, excluidos del workspace (pendiente)
docs/research/*             notas verificadas de los formatos Meshtastic y MeshCore (con URLs)
docs/STATUS.md              estado + plan
```

## Reglas del proyecto
* `meshstar-core` es `#![no_std]` + `alloc`, `#![forbid(unsafe_code)]`. Sin I/O: el motor
  `Node` recibe frames y tiempo, y devuelve frames y eventos. Nunca metas Meshtastic/MeshCore
  en el core.
* Nunca confíes en bytes recibidos por radio: toda validación en `Packet::decode` y en cada
  codec (`decode` devuelve `Err`, jamás panic). Añade un test de "basura aleatoria no
  paniquea" a cada codec nuevo.
* Criptografía real con crates auditados (`ed25519-dalek`, `x25519-dalek`,
  `chacha20poly1305`, `sha2`, `hmac`, `aes`, `ctr`, `ccm`). Noise implementado a mano en
  `crypto/noise.rs` siguiendo la especificación; no cambies primitivas sin actualizar
  `PROTOCOL_NAME_*`.
* Adaptadores foráneos: solo hechos verificados en `docs/research/*`; lo no verificado se
  marca `// UNVERIFIED:` y en la sección "Fidelity" del módulo. No inventes capacidades.
* Toda estructura acotada (caches, colas, buzón, reensamblado) tiene límite configurable y
  test de agotamiento.
* Estilo: `cargo fmt` (línea larga permitida, ver código existente), `cargo clippy` limpio,
  tests unitarios junto al módulo e integración en `tests/`.

## Comandos
```
cargo test --workspace                      # todo
cargo test -p meshstar-core                 # núcleo (unit + integration)
cargo test -p meshstar-protocols            # adaptadores
cargo build -p meshstar-core --no-default-features   # comprobar no_std
```
Los ejemplos ESP32 requieren `espup` y se compilan desde su propio directorio.

## Idioma
Código, comentarios y documentación técnica en inglés; comunicación con el usuario en
español.
