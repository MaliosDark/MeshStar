# MeshStar — Estado del proyecto y trabajo pendiente

Instantánea: 2026-09-16 (fin de la segunda sesión de reconstrucción). Léelo entero
antes de tocar código; `CLAUDE.md` tiene las reglas del repositorio.

## 1. Qué existe y funciona

`cargo test --workspace --release`: **183 tests, 0 fallos**. `cargo clippy` limpio salvo 3
avisos cosméticos.

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

Tráfico local, 2 msg/min: ZRP entrega 75/72/72/66 % a 30/100/300/1000 nodos con 13–15
transmisiones por mensaje; flooding protegido 48/43/39/34 %; flooding puro necesita 46–355
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

## 4. Pendiente, por prioridad

1. **Volcado y análisis del firmware original** (`tools/dump_heltec.sh`, luego `strings`,
   `esptool image_info`, documentar en `docs/research/ORIGINAL_FIRMWARE_NOTES.md`; añadir
   `sudo usermod -aG dialout $USER` para que las sesiones futuras puedan hablar con la placa).
2. **Compilar y flashear los ejemplos** en una placa que no sea la de referencia; ajustar a la
   versión de `esp-hal` instalada; validar los drivers en hardware real (sync word, CAD, RSSI).
3. **Store-and-forward a escala** (benchmark F: 13,6 %): el ANCHOR debe responder `WANT_KEY` con
   la clave de sus LEAF adjuntas siempre que la tenga; permitir al remitente sellar con la clave
   que llega en el RREP proxy; revisar tamaños de buzón y política de reintentos.
4. **Validar la interoperabilidad con dispositivos reales** (los vectores AES-CTR y ADVERT se
   derivaron del código fuente, no de capturas). Marcar como verificado en las notas.
5. Optimizaciones de protocolo pendientes de medir: m3 + primer DATA en un solo paquete;
   clave Ed25519 comprimida a 1 bit de signo en m2/m3 (-31 B); LINK_ACK sólo cuando no hay
   respuesta inmediata; beacons más cortos (direcciones truncadas en entradas de zona).
6. Zonas jerárquicas para tráfico no local a >300 nodos (caso B del benchmark).
7. Modelado de flooding gestionado de Meshtastic y repetidores MeshCore con más fidelidad en el
   simulador (hoy: flood genérico con tope de saltos).
8. Persistencia de estado en el firmware (identidad ya se guarda; falta buzón/rutas).

## 5. Cómo trabajar

```
cargo test --workspace --release          # todo
benchmarks/run.sh                         # reproduce BENCHMARKS.md (~25 min)
cargo run --release -p meshstar-sim --example debug -- 100 1800 2 zrp   # diagnóstico de protocolo
target/release/meshstar shell --nodes 12  # inspección interactiva
```
