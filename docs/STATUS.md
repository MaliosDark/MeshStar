# MeshStar — Estado del proyecto y plan de lo que falta

Fecha de esta instantánea: 2026-09-16. Sesión interrumpida a petición del usuario; este
documento es el punto de reanudación. Léelo entero antes de tocar código.

## 1. Qué existe y funciona

Workspace Rust (`cargo test --workspace` compila; ver excepciones en §3).

| Crate | Estado | Notas |
|---|---|---|
| `crates/meshstar-core` | **Funcional** (`no_std`+alloc). 63 tests unitarios + 12 de integración (9 pasan, 3 fallan, §3.1) | Todo el protocolo nativo: identidad Ed25519 + open addressing, paquetes, Noise XX/X, replay, fragmentación, vecinos/beacons, caché de rutas, ZRP (IARP+IERP), storm, transport, store-and-forward, power, motor `Node`, diagnóstico. |
| `crates/meshstar-protocols` | **Parcial, compila; 45 tests unitarios + 22 de integración pasan** | `model.rs` (UnifiedMessage, IdentityRef, ForeignIdentity, SecurityLevel), `adapter.rs` (trait `RadioProtocol`), `profiles.rs` (perfiles LoRa + `ScanSchedule`). **`meshtastic/` y `meshcore/` completos** (ver §2.1). `meshstar/`, `detector/`, `bridge/` son stubs. |
| `crates/meshstar-sim` | **Stub** (`//! TODO`) | |
| `crates/meshstar-cli` | **Stub** | |
| `crates/meshstar-radio-sx126x`, `-sx127x` | **Stub** (solo Cargo.toml con `embedded-hal`) | |
| `examples/esp32-*` | **No creados** (excluidos del workspace en `Cargo.toml`) | |
| `docs/research/MESHTASTIC_PROTOCOL_NOTES.md`, `MESHCORE_PROTOCOL_NOTES.md` | **Completos** (616 y 658 líneas, con fuentes citadas y lista de puntos NO verificados) | Base obligatoria para los adaptadores. |
| `docs/` (PROTOCOL, ZRP, PACKET_FORMAT, THREAT_MODEL, ARCHITECTURE, NODE_ROLES, INTEROP, COMPARISON, BENCHMARKS, HARDWARE, SIMULATOR) | **No escritos** | El diseño está en los doc-comments de cada módulo (`//!`), que son la fuente de verdad hasta que existan. |
| `README.md` | **No escrito** | |
| `LICENSE` | GPL-3.0 ✔ | |

### 1.1 Decisiones de diseño ya tomadas (no reabrir sin motivo)

* **Cabecera de 31 bytes** (`packet/mod.rs`): `ver|tipo, flags, ttl, hops, src(8), dst(8), packet_id(4), seq(2), next_hop(2), relay(2), plen`. Solo `ttl/hops/next_hop/relay` son mutables por salto; el resto es AAD del AEAD y del tag de red opcional (HMAC-SHA256 truncado a 4 bytes con `NetworkKey`). `next_hop`/`relay` son los 16 bits bajos de la dirección (pista, no identidad).
* **Dirección** = SHA-256("MeshStar/addr/v1"‖pubkey)[0..8]. Broadcast = 0xFF…; null = 0.
* **Noise XX** `Noise_XX_25519_ChaChaPoly_SHA256`; la clave estática Noise es la imagen X25519 de la clave Ed25519 (birational map); los payloads 2 y 3 llevan la pubkey Ed25519 y el verificador comprueba `to_montgomery(ed_pk) == rs` y `addr(ed_pk) == src`. Prólogo = `"MeshStar/xx/v1"‖initiator‖responder`. Mensaje 1 lleva `[role, epoch]`.
* **Transporte de sesión**: payload = `epoch u8 | ctr u24 | ct | tag16`; ventana anti-replay de 64; AAD = cabecera inmutable (+ frag_id en vez de packet_id si fragmentado); rekey = nuevo handshake con epoch+1.
* **Sobres (store-and-forward)** = Noise X (`-> e, es, s, ss`), prólogo `"MeshStar/env/v1"‖dst‖envelope_id`. Los DATA con flag `ENVELOPE` NO se cifran además por sesión. El destinatario responde con `ACK+ENVELOPE` sellado al remitente y `CONTROL MAILBOX_ACK` al ANCHOR.
* **Fiabilidad**: reintento = **nuevo packet_id** (los relays lo reenvían) + **mismo seq** (el receptor deduplica por `(src, seq)` y re-ACKea).
* **ZRP**: zona proactiva radio 2 (vector distancia acotado transportado en beacons); descubrimiento reactivo con anillo expansivo `[4,12,32,96]`, terminación temprana (target en zona), **proxy reply de ANCHOR** por LEAF dormida (con pubkey si `WANT_KEY`), poda por cobertura (`ZoneTable::covered_by`), relay adicional único si llega copia con coste < 70 %. RREQ no pasa por la seen-cache sino por `Ierp::observe_request`.
* **Storm**: seen-cache LRU, TTL acotado (rechazo por encima de `max_ttl`, `hops+ttl ≤ 255`), retardo aleatorio ponderado por SNR, cancelación por contador (3), supresión probabilística por densidad (umbral 6 vecinos, mínimo 25 %), un relay por paquete.
* **Métrica de ruta**: `link_cost(quality, congestion)` = 100·255/quality + congestión; coste acumulado en RREQ/RREP; penalización por antigüedad y fallos en `RouteEntry::effective_cost`. Hasta 2 rutas alternativas por destino.
* **Roles**: LEAF nunca relaya, se anuncia con beacon completo al despertar, hace FETCH a su ANCHOR; ANCHOR guarda paquetes para LEAF dormidas (`held_for_sleeping`) y sobres en `Mailbox` acotado.
* **Interop**: nada de Meshtastic/MeshCore entra en `meshstar-core`. Identidades foráneas son `IdentityRef::{Meshtastic(u32), MeshCore(..)}` y nunca se convierten en direcciones MeshStar. Toda `UnifiedMessage` lleva `SecurityLevel`; `Bridged{..}` envuelve el nivel original.

## 2. Trabajo en curso

### 2.1 Adaptadores Meshtastic y MeshCore — TERMINADOS (por agentes, tests en verde)
* `crates/meshstar-protocols/src/meshtastic/` (`mod.rs`, `header.rs`, `crypto.rs`, `proto.rs`, `ports.rs`, `profiles.rs`) + `tests/meshtastic_adapter.rs` (11 tests): cabecera 16 B LE, 9 presets × regiones con fórmula djb2 de slot, AES-128/256-CTR con nonce id‖from‖0, PSK por defecto y expansión, hash de canal (LongFast = 0x08), protobuf a mano (`Data/User/Position/Routing`), PKI DM (X25519→SHA-256→AES-256-CCM) codificación y decodificación, `detect()` puntuado, vectores AES-CTR de las notas reproducidos byte a byte. Límite práctico de texto 232 B. `periodic()` emite NodeInfo.
* `crates/meshstar-protocols/src/meshcore/` (`mod.rs`, `packet.rs`, `identity.rs`, `crypto.rs`, `messages.rs`, `profiles.rs`) + `tests/meshcore_adapter.rs` (11 tests): byte de cabecera/path, ADVERT firmado (verify_strict), ECDH sin KDF + AES-128-ECB + HMAC-SHA256 truncado 2 B, GRP_TXT canal "Public" (hash 0x11 derivado), TXT_MSG directo, ACK, GRP_DATA, `detect()`, `periodic()` ADVERT.
* Ambos módulos tienen una sección "Fidelity" en el doc-comment con lo verificado, lo `UNVERIFIED` y lo no implementado (Meshtastic: canales AEAD de develop, XEdDSA, texto comprimido, Telemetry/Admin/Traceroute; MeshCore: transport codes, PATH return, ANON_REQ login, MULTIPART, TRACE). Mantén esas marcas.

## 3. Qué falta y cómo se iba a implementar

### 3.1 Tres tests de integración que fallan (`crates/meshstar-core/tests/integration.rs`)
1. `broadcast_with_group_key`: probable causa: en `handle_broadcast_data` un nodo con clave sin tag válido ya se rechaza en `Packet::decode` (bien), pero los nodos con clave que reciben el broadcast por relay quizá no lo reciben porque `maybe_relay_flood` aplica `covered_by` en cadena (nodo 1 cubre a 2 respecto a 0…). Depurar imprimiendo `counters.relay_suppressed_covered`; la poda por cobertura debería exigir que **todos** los vecinos del receptor sean vecinos del transmisor, y `adjacency` solo contiene la lista anunciada; comprobar que el beacon incluye a los vecinos a distancia 1 (`advertisement()` filtra `distance < radius.max(2)` → sí). Alternativa: aplicar la poda solo a RREQ, no a DATA broadcast.
2. `fragment_loss_is_retried`: con 15 % de pérdida el ACK/reintento tarda; ver si `Reassembler` con `Duplicate` de fragmentos reintentados bloquea (un reintento manda fragmentos nuevos con **nuevo frag_id**, pero el receptor mantiene el set viejo hasta el timeout de 60 s → correcto, no bloquea). Probable causa: el reintento reencripta con nuevo ctr pero **la AAD usa el frag_id nuevo**, correcto… revisar `send_session_packet` cuando `body` cabe sin fragmentar en reintento (no ocurre). Añadir trazas.
3. `leaf_anchor_store_and_forward`: cadena sender→anchor→leaf. Comprobar: (a) el sender aprende la pubkey de la LEAF (necesita `RREP` con `HAS_KEY` del proxy ANCHOR; el ANCHOR solo la tiene si la LEAF envió beacon completo → `send_beacon` fuerza `full` para LEAF ✔); (b) `deliver_envelope` en el sender: `zone.anchor_for(leaf)` requiere que la entrada de zona de la LEAF tenga `next_hop` = ANCHOR con flag ANCHOR; el ANCHOR anuncia la LEAF en `attached` → se inserta con `SLEEPING|LEAF` a distancia 2 ✔; (c) tras `Stored`, la LEAF al despertar hace `send_fetch` → necesita sesión con el ANCHOR (handshake) → `drain_queued` envía FETCH ✔; (d) el ANCHOR entrega `DATA+ENVELOPE` a la LEAF; la LEAF abre el sobre y manda `ACK+ENVELOPE` al sender vía `route_unicast` (necesita ruta hacia el sender: `next_hop_for(sender)` → probablemente **no hay ruta** desde la LEAF (nunca vio tráfico del sender) → arranca un descubrimiento que la LEAF, que no relaya y se duerme, puede no completar). Solución prevista: la LEAF encamina sus ACK de sobre **a través de su ANCHOR** (`next_hop = attached_anchor`) sin descubrimiento; y el ANCHOR reenvía por ruta inversa hacia el sender (la tiene). Implementar en `handle_unicast_data`: si `cfg.role == Leaf` y `attached_anchor.is_some()`, fijar `next_hop` = anchor y encolar directamente.

### 3.2 Simulador (`crates/meshstar-sim`) — no empezado
Diseño previsto:
* `World { nodes: Vec<SimNode>, now, rng, events: BinaryHeap<TxEnd> }`, `SimNode { node: Node, pos (x,y), vel, role, online: bool, sleeping via Node::is_awake, airtime_tx/rx, battery_mah estimada }`.
* Modelo de enlace: log-distance path loss (n≈2.7–3.2 configurable), RSSI = Ptx − PL; SNR = RSSI − noise_floor(BW); PER = f(SNR − sensibilidad) sigmoide; **colisiones**: al iniciar una TX se calcula fin = now + airtime; una recepción falla si otra TX solapa en el receptor con SIR < 6 dB (efecto captura).
* Movilidad random-waypoint; nodos offline por intervalos; topologías: `grid`, `random`, `clustered`, `line`, `ring`.
* Generador de tráfico: N mensajes unicast entre pares aleatorios (o a leaf), broadcast, clases Unreliable/Acknowledged/StoreAndForward.
* **Métricas**: delivery ratio, latencia (media/p50/p95), hops medios, retransmisiones, overhead de control (bytes control/bytes total), airtime total y por nodo, duplicados (rx_duplicates), convergencia de rutas (tiempo hasta RouteFound), relays cancelados/suprimidos, carga de gateway.
* Modo comparación: `RoutingMode::Zrp` vs `RoutingMode::Flood` (ya soportado en `NodeConfig`); para "flood puro" poner `StormConfig{counter_threshold:255, density_threshold:255}`.
* Salida JSON + tabla; `benchmarks/run.sh` con barrido de tamaños (50/200/500/1000 nodos) → `docs/BENCHMARKS.md`.
* Extensión interop: `SimNode` con `NodeKind::{MeshStar, Meshtastic, MeshCore, Gateway{radios: Vec<LoRaProfile>}}`; los nodos foráneos usan los adaptadores para generar/decodificar frames; el medio filtra por `LoRaProfile` (solo se decodifica si el receptor está en el mismo perfil en ese instante, según `ScanSchedule`).

### 3.3 CLI (`crates/meshstar-cli`, binario `meshstar`) — no empezado
`clap` con subcomandos: `identity {new,show}`, `addr`, `packet decode <hex>`, `sim {run,compare,sweep,inspect}`, `shell` (REPL sobre un `World` pequeño con `neighbors|routes|zone|sessions|counters|store|radio|send|step|discoveries`), `protocols`, `scan`, `networks`, `neighbors --all-protocols`, `send --protocol X`, `bridge {status,enable,disable,routes}`. Log con `env_logger` (`RUST_LOG`). `Node::diagnostics()` ya devuelve todo lo necesario serializable.

### 3.4 Capa de adaptadores (`meshstar-protocols`) — parcial
* `meshstar/mod.rs`: adaptador nativo: `detect` = `Packet::decode` OK + versión + (si hay clave) tag válido → 100; `decode` → `UnifiedMessage` (DATA broadcast/plain; unicast cifrado → `Opaque` + `MeshStarE2E`); `encode` = broadcast/plain (el unicast cifrado va por `Node`, no por el adaptador).
* `detector/mod.rs`: `Detector { adapters }` → `detect_all(frame, meta, ctx) -> Detection { best: ProtocolId, score, all_scores }`; umbral configurable (por defecto 60); si dos protocolos > umbral y la diferencia < 15 → `Unknown` (ambiguo); nunca llama a `decode` bajo umbral. Tests: frames MeshStar/Meshtastic/MeshCore reales de los tests de cada adaptador, basura aleatoria → Unknown.
* `bridge/`: `policy.rs` (reglas `allow/deny` por protocolo origen/destino, canal, tipo, identidad, `SecurityLevel`; por defecto **deny all**, bridge desactivado), `loop.rs` (`bridge_origin`, `bridge_path` con máx. 2 cruces, cache de `canonical_digest` con ventana 10 min, prohibido volver a un protocolo ya presente en `bridge_path`), `dedup.rs` (LRU por `canonical_digest` + `(source,message_id)`), `translate.rs` (matriz de capacidades: solo Text/Position/Ack; truncado de texto con marca `[…]`; `Unsupported` → `Failed` con motivo), `gateway.rs` (`Gateway { mode: Native|Compat|Bridge, radios: Vec<RadioSlot{profile, schedule}>, adapters, policy, cache, rate_limiter (token bucket por protocolo destino) }`). Al traducir, `security = Bridged{via, gateway, original}`.
* `docs/INTEROP.md`: modos, matriz de capacidades, frontera de seguridad, trade-offs de radio única vs multi-radio vs scan.

### 3.5 Drivers de radio y ejemplos ESP32 — no empezados
* `meshstar-radio-sx126x`: comandos SPI (SetStandby, SetPacketType, SetRfFrequency, SetPaConfig, SetTxParams, SetModulationParams, SetPacketParams, SetDioIrqParams, Write/ReadBuffer, SetTx/SetRx, GetIrqStatus/Clear, GetPacketStatus, GetRxBufferStatus, SetBufferBaseAddress, SetRegulatorMode, SetDio2AsRfSwitchCtrl, SetDio3AsTcxoCtrl, Calibrate, SetSleep, CAD). Sync word con `LoRaProfile::sync_word_sx126x()`. Implementa `meshstar_core::radio::Radio` sobre `embedded-hal 1.0` (`SpiDevice`, `OutputPin`, `InputPin`, `DelayNs`). Compilable en host (tests con SPI falso).
* `meshstar-radio-sx127x`: registros (RegOpMode, RegFrf, RegPaConfig, RegModemConfig1/2/3, RegFifo*, RegIrqFlags, RegPktRssiValue, RegPktSnrValue, RegSyncWord…).
* `examples/esp32-sx1262` y `esp32-sx1276`: Rust `no_std` con `esp-hal` (bucle: radio.receive → node.on_radio_rx; node.poll; node.next_tx → radio.transmit; consola serie con comandos `id nb rt zone ss cnt store radio log`). No se pueden compilar aquí (toolchain Xtensa); documentar cómo (`espup`).

### 3.6 Documentación — no empezada (salvo research)
README técnico, PROTOCOL.md (máquinas de estado, tablas de bytes), ZRP.md, PACKET_FORMAT.md, THREAT_MODEL.md (activos, atacantes, mitigaciones por mecanismo, límites: plano de control no autenticado más allá de beacons completos y tag de red; sobres sin PFS para el receptor; metadatos visibles: direcciones, tamaños, tiempos), ARCHITECTURE.md (diagrama), NODE_ROLES.md (LEAF/ANCHOR), COMPARISON.md (vs Meshtastic/MeshCore, sin atacarlos), HARDWARE.md, SIMULATOR.md, BENCHMARKS.md (con números reales del simulador).

## 4. Orden recomendado para reanudar
1. Comprobar agentes (§2.1) y `cargo test --workspace`.
2. Arreglar los 3 tests (§3.1) — el motor está casi completo; son ajustes de encaminamiento.
3. Simulador + benchmarks (es lo que valida "escala mejor que flooding").
4. `meshstar/`, `detector/`, `bridge/` en `meshstar-protocols`.
5. CLI.
6. Drivers + ejemplos ESP32.
7. Documentación final (extraer de los doc-comments y de este archivo).
