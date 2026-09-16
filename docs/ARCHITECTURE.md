# Architecture

## System view

```
                                  application / UI / gateway policy
                                               │
                    ┌──────────────────────────┴───────────────────────────┐
                    │              meshstar-protocols                      │
                    │  UnifiedMessage · IdentityRef · SecurityLevel        │
                    │  ┌──────────┐ ┌─────────────┐ ┌───────────┐          │
                    │  │ MeshStar │ │ Meshtastic  │ │ MeshCore  │ adapters │
                    │  │ adapter  │ │ adapter     │ │ adapter   │          │
                    │  └────┬─────┘ └──────┬──────┘ └─────┬─────┘          │
                    │       └──────── Detector ───────────┘                │
                    │       policy · loop guard · dedup · translate        │
                    │                 Gateway                              │
                    └──────────────┬───────────────────────┬───────────────┘
                                   │ frames                │ frames
                    ┌──────────────┴───────────┐   ┌───────┴──────────────┐
                    │      meshstar-core       │   │  foreign radio slot  │
                    │  Node (the engine)       │   │  (time-shared or     │
                    └──────────────┬───────────┘   │   dedicated radio)   │
                                   │ Radio trait   └──────────────────────┘
                    ┌──────────────┴───────────┐
                    │  sx126x / sx127x driver  │   (or the simulator's channel)
                    └──────────────────────────┘
```

## meshstar-core module graph

```
                 ┌──────────────────────────── node ────────────────────────────┐
                 │  tx.rs (send, route, beacons, RREQ/RREP, envelopes, hop ack) │
                 │  rx.rs (validate, dedup, dispatch, forward, ZRP handlers)     │
                 │  session.rs (Noise XX state machine, rekey, NO_SESSION)       │
                 │  diag.rs (counters, snapshot)                                 │
                 └──┬──────┬──────┬───────┬────────┬────────┬────────┬─────────┘
                    │      │      │       │        │        │        │
              ┌─────┴┐ ┌───┴──┐ ┌─┴────┐ ┌┴──────┐ ┌┴──────┐ ┌┴──────┐ ┌┴────────────┐
              │packet│ │crypto│ │neigh-│ │routing│ │  zrp  │ │ storm │ │store_forward│
              │      │ │noise │ │bor   │ │cache  │ │zone + │ │seen · │ │ mailbox     │
              │header│ │sessn.│ │beacon│ │cost   │ │ierp   │ │jitter │ │ envelopes   │
              │codec │ │envel.│ │table │ │       │ │msgs   │ │suppr. │ │             │
              └──┬───┘ └──┬───┘ └──────┘ └───────┘ └───────┘ └───────┘ └─────────────┘
                 │        │
           ┌─────┴───┐ ┌──┴─────┐    ┌─────────────┐ ┌───────┐ ┌────────┐ ┌──────────┐
           │identity │ │fragmen-│    │ transport   │ │ power │ │ radio  │ │ platform │
           │Ed25519  │ │tation  │    │ retries,ack │ │ duty  │ │ HAL,   │ │ clock,   │
           │address  │ │        │    │ seq windows │ │ sleep │ │ profile│ │ storage  │
           └─────────┘ └────────┘    └─────────────┘ └───────┘ └────────┘ └──────────┘
                                          protocol (constants, types, errors)
```

Dependencies point downwards only; `node` is the sole module that knows
about all the others. Nothing below `node` performs I/O or knows the time
except through values passed in.

## Data flow of one message (A → D, three hops, first contact)

```
A: send_message(D, "hi", Acknowledged)
   │ no session, no route
   ├─ start Noise XX (m1)  ──┐
   └─ ROUTE_REQUEST(D) + m1 ─┘  ── flood, TTL 4, storm rules, coverage pruning ──▶ B ──▶ C ──▶ D
D: target: responder_start(m1) → m2; ROUTE_REPLY(cost) + m2 ◀── reverse path, staggered ◀── C ◀── B
A: absorb route; initiator_continue(m2) → session; HANDSHAKE m3 ─▶ B ─▶ C ─▶ D   (each hop confirmed)
A: DATA(session, seq, ACK_REQUEST) ─▶ B ─▶ C ─▶ D                               (each hop confirmed)
D: session install on m3; decrypt; deliver; ACK(seq) ─▶ C ─▶ B ─▶ A
A: Delivered{handle, rtt}
```

Second message A → D: DATA only (session and route cached).
Message to a sleeping LEAF L attached to ANCHOR N: sealed envelope → N stores
→ L wakes, beacons, FETCHes → N delivers → L opens, ACKs A, tells N.

## Crates and boundaries

| crate | may depend on | never contains |
|---|---|---|
| meshstar-core | crypto crates, serde | I/O, foreign protocol knowledge |
| meshstar-protocols | core (types, packet codec, LoRaProfile) | routing or session logic |
| meshstar-sim | core, (protocols for interop scenarios) | production code paths |
| meshstar-cli | all | protocol logic |
| meshstar-radio-* | core::radio, embedded-hal | protocol logic |
| examples/esp32-* | core, a driver | anything the host cannot also run |
