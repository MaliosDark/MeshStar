# MeshStar — Estado del proyecto y trabajo pendiente

Instantánea: 2026-09-16 (fin de la segunda sesión de reconstrucción). Léelo entero
antes de tocar código; `CLAUDE.md` tiene las reglas del repositorio.

## 1. Qué existe y funciona

`cargo test --workspace --release`: **183 tests, 0 fallos**. `cargo clippy --workspace --all-targets`: 0 avisos.

| Componente | Estado |
|---|---|
| `crates/meshstar-core` | **Completo y calibrado.** Identidad Ed25519 + open addressing; cabecera de 31 B con tag de red; Noise XX / Noise X; ventana anti-replay; fragmentación acotada; beacons con calidad de enlace (margen SNR + ratio de entrega + ETX); tabla de zona por coste; caché de rutas con TTL y alternativas; ZRP (anillo expansivo 4/12/32, respuesta sólo del destino o proxy ANCHOR, respuestas escalonadas por coste, m1/m2 de Noise dentro de RREQ/RREP); protección de tormentas; **fiabilidad por salto** (ACK implícito + LINK_ACK, reintentos, re-encaminado); transporte con retries; buzón store-and-forward; energía (LEAF con temporizadores desplazados); recuperación de sesión (NO_SESSION). 63 unit + 15 integración. |
| `crates/meshstar-protocols` | **Completo.** Modelo unificado, trait `RadioProtocol`, perfiles + `ScanSchedule`, adaptador nativo, **Meshtastic** y **MeshCore** (desde fuentes oficiales, secciones "Fidelity" con lo `UNVERIFIED`), detector con Confirmed/Probable/Unknown, bridge (política deny-all por defecto, anti-bucle, dedup por id/digest/texto, traducción conservadora, gateway con rate limit). 53 unit + 15 interop + 22 de adaptadores. |
| `crates/meshstar-sim` | **Completo.** Modelo de enlace/colisiones/LBT, topologías, movilidad, cortes, tráfico (random/partners/**local**/sinks/leaves), duty cycle 1 %, métricas, 3 estrategias, **escenarios interop** (nodos foráneos a nivel de trama, gateways mono/multi-radio). |
| `crates/meshstar-cli` | **Completo.** `identity`, `addr`, `decode`, `sim {run,compare,sweep,inspect,template,from-json,interop}`, `shell`, `protocols`, `profiles`, `scan`, `networks`, `neighbors`, `send --protocol`, `bridge {status,enable,disable,routes}`. |
| `crates/meshstar-radio-sx126x/-sx127x` | **Escritos con tests sobre bus SPI simulado.** No probados en hardware. |
| `examples/esp32-sx1262`, `esp32-sx1276` | **Escritos, no compilados** (requieren toolchain Xtensa/`espup`; la API de `esp-hal` 0.23 puede requerir ajustes). |
| Documentación | README, PROTOCOL, PACKET_FORMAT, ZRP, THREAT_MODEL, NODE_ROLES, INTEROP, COMPARISON, SIMULATOR, HARDWARE, ARCHITECTURE, **BENCHMARKS con números medidos** (`benchmarks/run.sh`). |
| `firmware-dump/` | **Pendiente de ti**: `sudo tools/dump_heltec.sh` vuelca (solo lectura) el Heltec con el firmware original. |

## 2. Resultados clave (docs/BENCHMARKS.md)

Tráfico local, 2 msg/min: ZRP entrega 72/68/69/69 % a 30/100/300/1000 nodos con 10–16
transmisiones por mensaje; flooding protegido 45/40/37/39 %; flooding puro necesita 51–250
transmisiones por mensaje. Con tráfico aleatorio a través de toda la red todo degrada
(caso peor); ZRP sigue siendo 2–2,5× mejor que flooding protegido.

## 3. Decisiones de diseño cerradas (no reabrir sin datos del simulador)

* Perfil por defecto SF8/125 kHz/4·5, sync 0x1A; beacons cada 120 s (adaptativo ×4), zona
  radio 2, 6 entradas de zona por beacon rotando, beacon completo cada 6.
* Coste de enlace cuadrático en el déficit de calidad; la tabla de zona y el next hop se eligen
  por coste, no por saltos.
* Sólo el destino (o el ANCHOR proxy de una LEAF) responde a un RREQ; las respuestas se escalonan
  por coste y se cancelan al oír una mejor.
* Fiabilidad por salto con timeout = 3×airtime + 1,5 s, 2 reintentos, 1 re-encaminado.
* Sesiones: idle 4 h, máx 24 h; m1 en RREQ, m2 en RREP; m3 se reenvía ante NO_SESSION (máx 3) y
  después se reinicia la sesión.
* Los adaptadores foráneos nunca tocan `meshstar-core`; el bridge está apagado por defecto y el
  tráfico E2E de MeshStar nunca se traduce.
* Modelo de host para LEAF: cualquier nodo siempre encendido aloja a las LEAF que lo eligen
  (la LEAF nombra a su host en su beacon); ANCHOR preferido (bonus de calidad +60, buzón
  grande). Secuencia de despertar: beacon primero, FETCH sólo si nadie responde; jitter ±20 %
  en el sueño; extensión de ventana por actividad con tope de 5 ventanas.

## 4. Pendiente, por prioridad

1. ~~Volcado y análisis del firmware original~~ **Hecho** (2026-09-16): `firmware-dump/`
   (fuera de git: contiene la clave privada) y `docs/research/ORIGINAL_FIRMWARE_NOTES.md`.
   Portado ya: identidad desde NVS (`platform::nvs`, verificado contra el volcado), perfiles
   MeshCore EU SF8/SF9 (`eu_uk_scan`) y **sondeo CAD** en el driver SX126x (mejor que el
   ciclo de 15 s del original), pantalla OLED con páginas Status/Signal/Nodes/Radio y botón.
   Pendiente: protocolo BLE NUS de la app compañera (sólo se conoce `0x04 SEND_MSG`), ADR,
   lectura de batería, y decidir si se ofrece el suite `Noise_XX_25519_AESGCM_BLAKE2b`
   (sólo útil si existen más nodos con el firmware original).
2. ~~Compilar y flashear los ejemplos~~ **Hecho** (2026-09-16): dos Heltec V3 con el firmware Rust
   intercambian beacons, descubren ruta, completan Noise XX y entregan mensajes con ACK.
   Grabado con `tools/flash_example.sh` (esptool; espflash 4 no acepta imágenes sin app
   descriptor). Pendiente en hardware: revisar lecturas RSSI a 0 intermitentes en el driver
   SX126x, falsos positivos de `channel_busy`, OLED/botón (sin confirmar visualmente), sondeo CAD.
3. **Store-and-forward a escala** (benchmark F: 19,7 % entregado, 18 % confirmado tras el
   rediseño LEAF/host). Lo que queda es la fiabilidad de la respuesta de descubrimiento a varios
   saltos (el remitente necesita llegar al host de la LEAF para obtener la clave). Ideas: que
   cualquier nodo que conozca la clave de una LEAF pueda adjuntarla en un RREP de "sólo clave"
   sin ruta; caché de claves de LEAF distribuida en beacons completos de los hosts (32 B por
   LEAF, rotando); reintento del RREQ de clave con TTL pequeño hacia el host conocido.
4. ~~Validar la interoperabilidad~~ **Hecho** (2026-09-16): MeshCore companion v1.17.1 y
   Meshtastic 2.7.26 reales, ambos en los dos sentidos (ver docs/INTEROP.md). **Modo scan
   con una sola radio validado**: A en MeshStar + sondeos CAD recibe 18-20/20 Meshtastic,
   9-11/10 MeshCore y 10/10 nativo con acks (el perfil MeshStar pasa a preámbulo de 32
   símbolos para sobrevivir al barrido). Falta: responder en la red foránea desde scan,
   `NodeInfo` Meshtastic, reloj para timestamps foráneos.
5. Optimizaciones de protocolo pendientes de medir: m3 + primer DATA en un solo paquete;
   clave Ed25519 comprimida a 1 bit de signo en m2/m3 (-31 B); LINK_ACK sólo cuando no hay
   respuesta inmediata; beacons más cortos (direcciones truncadas en entradas de zona).
6. Zonas jerárquicas para tráfico no local a >300 nodos (caso B del benchmark).
7. Modelado de flooding gestionado de Meshtastic y repetidores MeshCore con más fidelidad en el
   simulador (hoy: flood genérico con tope de saltos).
8. Persistencia de estado en el firmware (identidad ya se guarda; falta buzón/rutas).
9. UI de dispositivo (hecha 2026-09-16, ver docs/UI.md): barra de estado invertida, listas
   unificadas con insignias de protocolo y etiqueta de seguridad, chats, redes, señal con
   sparkline, nodo, ajustes; falta: responder desde el dispositivo (app BLE), toggle de
   bridge por red, apagado de pantalla por tiempo, ajustes persistentes.

## 5. Cómo trabajar

```
cargo test --workspace --release          # todo
benchmarks/run.sh                         # reproduce BENCHMARKS.md (~25 min)
cargo run --release -p meshstar-sim --example debug -- 100 1800 2 zrp   # diagnóstico de protocolo
target/release/meshstar shell --nodes 12  # inspección interactiva
```
