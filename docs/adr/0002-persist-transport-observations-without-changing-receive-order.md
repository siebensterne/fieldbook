# ADR 0002: Persist transport observations without changing application receive ordering

> Historical record. Test paths named below were retired under RRP-002
> (owner directive D11) and are not available in the active tree. This
> document is preserved unchanged except for this notice; see
> `docs/synthetic-asset-retirement-2026-11-23.md` for the current state.

- **Status:** Accepted
- **Date:** 2026-11-16
**Decision owner:** Project maintainers
**Implementation status:** Implemented (S1a and S1b). Writers emit schema v2
  with typed transport observations; `read_records()` remains data-only and
  `read_observations()` exposes data plus native controls. v1 journals and the
  v1 golden fixture remain readable by this build. The normative content below
  is unchanged; only this status line moved from "pending" to "implemented".
**Related:** [Raw-frame journal](../raw-frame-journal.md),
  [requirement/test matrix](../requirement-test-matrix.md),
  [architecture](../architecture.md),
  [programme status](../programme-status.md).

## 1. Context

The current journal schema is v1. It records application data frames with a
per-source `(connection_epoch, receive_seq)` ordering fence. Native WebSocket
control frames are not journaled. That boundary is deliberate and protected by
`tests/e2e_mock_exchange.rs::journal_accounts_for_every_delivered_payload`:
transport controls must not increase the legacy application-record count or
consume the application's receive sequence.

The session layer already knows protocol facts that the journal cannot prove:
`SessionSignal::HeartbeatAck`, `PeerPing`, and `ProtocolControl`. The journal
currently records only frame kind, decode outcome, and payload bytes. It
therefore cannot preserve the adapter's interpretation or heartbeat mechanism.

There are also transport-boundary losses and classification errors:

`ws::next_payload()` automatically answers an inbound native Ping and
   returns `Idle`, discarding the Ping payload before the adapter or worker can
   retain it.
Kalshi's native Pong is represented as `FrameKind::Binary`, even though
   it is a native WebSocket control frame and not a binary data frame.
Polymarket's native Pong is transport plumbing, not an acknowledgement of
   Polymarket's application-text heartbeat. Its native Pong is currently
   discarded; Polymarket's application heartbeat is the text `PING`/`PONG`
   exchange.
`SessionSignal` and the mechanism selected by each adapter are not persisted
   in journal v1. Reconstructing them later from bytes is not a reliable
   substitute for the adapter's typed observation.
5. The requirement matrix records transport idle events as out of scope. That
   statement was correct for the v1 data-record interface, but it is no longer
   the desired audit contract for a complete observation journal.

The journal must preserve facts at the boundary where they are observed while
keeping the book-recovery fence unchanged.

## 2. Decision

Adopt a v2 journal observation model with **three independent per-source,
per-connection-epoch sequences**:

| Sequence | Scope | Advances when | Purpose |
|---|---|---|---|
| `receive_seq` | Inbound WebSocket data frames | A Text or Binary frame is received | Application receive fence used by collector/book ordering |
| `control_seq` | Native WebSocket control frames | A Ping or Pong is observed inbound or outbound | Accounts for native transport controls without consuming the data fence |
| `observation_seq` | All retained observations | Any inbound or outbound observation is appended | Preserves data/control interleaving in the order the worker observes it |

All three sequences are scoped by `(SourceId, connection_epoch)` and reset
when that source establishes a new connection. `observation_seq` is strictly
monotonic within that scope. `receive_seq` and `control_seq` are independently
monotonic within their respective scopes. Wall-clock timestamps are useful
metadata but are not a substitute for `observation_seq`.

The existing application receive fence remains authoritative for order-book
recovery. Control observations never advance it. The existing
`journal_accounts_for_every_delivered_payload` assertion must retain its
meaning: `read_records()` returns application data records only, and their
count equals the number of delivered application payloads accounted by that
test.

### 2.1 Typed protocol facts

Move serializable, adapter-independent protocol semantics into a small shared
`src/protocol.rs` module. It owns only:

`SessionSignal` (including the required `PeerPong` variant for an outbound response);
`HeartbeatMechanism` (`ApplicationText`, `WebSocketControl`, `Disabled`);
`FrameDirection` (`Inbound`, `Outbound`);
`FrameClassification` (`Data { frame_kind }` or `Control { opcode }`);
`ControlOpcode` (`Ping`, `Pong`).

The adapter remains responsible for assigning the signal and heartbeat
mechanism. The journal serializes those facts; it must not infer them from the
payload. Adapter-specific JSON decoding and exchange-event semantics stay in the
adapters.

Every v2 observation contains at least:

```text
source
connection_epoch
observation_seq
direction
observed_at_us
record_kind / frame_classification
session_signal
heartbeat_mechanism
payload
send_result (for outbound observations)
```

An inbound data observation additionally contains `receive_seq`; a native
control observation additionally contains `control_seq`. Outbound data
observations (for example Polymarket's text `PING`) and outbound control
observations are retained with direction and send result, but do not pretend to
be inbound book data. Heartbeat acknowledgement observations preserve their
correlation bytes when the venue supplies them. Unmatched, mismatched, and late
responses remain observations; classification as a failed or unmatched
acknowledgement must not erase the wire evidence.

### 2.2 Venue-specific classification

The adapter/mechanism distinction is normative:

| Observation | WebSocket frame class | Session signal | Sequence |
|---|---|---|---|
| Polymarket text `PING` | Data: Text | `PeerPing` | `receive_seq` inbound |
| Polymarket text `PONG` | Data: Text | `HeartbeatAck` | `receive_seq` inbound |
| Polymarket native Ping | Control: Ping | `PeerPing` | `control_seq` inbound |
| Polymarket native Pong | Control: Pong | `ProtocolControl` | `control_seq` inbound |
| Kalshi native Ping | Control: Ping | `PeerPing` | `control_seq` inbound |
| Kalshi native Pong | Control: Pong | `HeartbeatAck` | `control_seq` inbound |
| Server-Ping response Pong | Control: Pong | `PeerPong` | `control_seq` outbound |

For a server Ping, the transport boundary must preserve the inbound Ping,
send a matching Pong, and return both observations to the worker. A successful
outbound Pong is recorded with `direction = Outbound` and a successful send
result. It produces no market-data event. If sending fails, the failure path
must retain the inbound Ping evidence and represent the failed send attempt;
it must not silently discard the already observed Ping.

Polymarket text `PING`/`PONG` remains application **data** even though the
adapter interprets it as a heartbeat. The mechanism is `ApplicationText`.
Kalshi's native control heartbeat uses `WebSocketControl`. A venue with no
heartbeat mechanism uses `Disabled`; the journal must not infer one from an
empty payload or a timer sentinel.

### 2.3 Journal APIs and compatibility

The writer moves to schema v2. Keep two explicit read contracts:

```rust
pub fn read_records(run_directory: &Path) -> Result<Vec<JournalRecord>>;
pub fn read_observations(run_directory: &Path) -> Result<Vec<JournalObservation>>;
```

`read_records()` remains data-only and is the compatibility API for existing
application payload consumers and the protected accounting test.
`read_observations()` returns both application data and native transport
controls in `observation_seq` order. It exposes typed signals, mechanisms,
direction, payloads, independent sequence fields, and outbound send results.

Readers must support:

- v1: existing data-only meaning; no session signal or heartbeat mechanism is
  fabricated because v1 did not store those facts;
- v2: data and control observations with explicit typed metadata and all three
  sequence domains.

Keep the existing v1 golden fixture unchanged. Do not rewrite it as v2. Writers
emit v2 only; v1 segments are read but never rewritten. Unsupported schema
versions, truncated records, malformed lengths, and checksum failures fail
closed.

### 2.4 Ordering and fences

For one `(SourceId, connection_epoch)`, `observation_seq` captures the order in
which the worker retains observations. This is the authoritative interleaving
between data and controls. Independent `receive_seq` and `control_seq` answer
which domain an observation belongs to; timestamps do not establish the exact
interleaving.

The collector's book fence remains `(connection_epoch, receive_seq)`. A
transport Ping or Pong, including an automatically generated response, cannot
advance the book fence, anchor a snapshot, reset a sequence tracker, or satisfy
an application-level Polymarket heartbeat. Application-text PING/PONG are data
frames and therefore advance inbound `receive_seq`, but still produce no
market-data event and do not update an instrument's activity timestamp.

## 3. Explicitly preserved invariants

This ADR does **not** weaken or supersede:

exact-once accounting of every delivered application data payload;
contiguous per-source inbound `receive_seq` for data observations;
rejection journaling for malformed or protocol-rejected data payloads;
the protected assertion that transport controls do not appear in
  `read_records()` and do not consume `receive_seq`;
- the rule that market data cannot satisfy a heartbeat;
- source/epoch recovery fencing and stale-generation rejection;
- unchanged SBE output schema and existing SBE consumer compatibility.

It supersedes only the earlier statement that transport-level idle/control
events are out of scope for **all** journal evidence. They remain outside the
legacy data-only `read_records()` stream and inside the new complete
`read_observations()` stream once S1a/S1b are implemented.

## 4. Implementation plan and acceptance criteria

S1a and S1b form one evidence increment. Neither is complete in isolation.

### S1a — Preserve transport observations

Change `WsPayload` to surface typed Text, Binary, Ping, and Pong frames with
   the original payload bytes. Do not collapse native controls into `Idle`.
2. Keep the WebSocket layer responsible only for transporting frames. The
   adapter classifies the venue-specific heartbeat semantics.
On an inbound Ping, return both the inbound Ping and matching outbound Pong
   observations, including the Pong send result.
Carry `SessionSignal`, `HeartbeatMechanism`, direction, classification,
   opcode, and correlation data to the worker. Keep control observations
   separate from `ExchangeEvent` decoding.
Move the shared protocol types listed in §2.1 into `src/protocol.rs` to avoid
   making the journal depend on the session module.
6. Capture outbound heartbeat sends (Polymarket text PING and Kalshi native
   Ping) only after the send succeeds; preserve direction and send result.

S1a tests must cover inbound Ping with a non-empty payload, matching outbound
Pong, inbound native Pong, following application data, and send failure. The
transport must not produce a market-data event for a native control frame.

### S1b — Persist and read observations

Bump writers to journal schema v2 and add typed v2 observation headers.
Preserve v1 readers and add the v2 `read_observations()` API.
Keep `read_records()` data-only and preserve its existing count semantics.
Preserve per-source ordering validation, with independent continuity checks
   for `receive_seq`, `control_seq`, and `observation_seq` within each epoch.
5. Preserve checksums, segment rotation, manifest accounting, queue
   backpressure, failure latching, and bounded shutdown semantics for both
   observation kinds.
6. Retain v1 fixtures and add v2 golden fixtures. Never regenerate v1 evidence
   into a v2-only fixture.

Required journal tests:

- read the checked-in v1 golden segment;
- read v2 data-only observations;
- read a v2 segment with native controls;
- read a v2 segment with Polymarket text heartbeats;
- validate checksums and all sequence domains;
- reject unsupported versions, malformed/truncated records, and corruption;
replay matching v1/v2 application data into identical core state;
prove that control observations never become `ExchangeEvent`s; and
prove `journal_accounts_for_control_observations_without_advancing_receive_seq`
  with inbound Ping, outbound Pong, inbound Pong, and ordinary data in one
epoch.

The protected `journal_accounts_for_every_delivered_payload` test remains
unchanged in meaning and must continue to pass.

## 5. Consequences

**Positive:** the journal can prove what the adapter and transport observed,
including control direction, opcode, heartbeat mechanism, correlation evidence,
and interleaving, without changing order-book recovery ordering. Existing
data-only readers remain usable.

**Costs:** the format and reader become more complex; sequence validation must
be domain-aware; session adapters must preserve outbound and inbound wire
evidence; v1 compatibility fixtures and tests must remain permanently
maintained.

**Non-goals:** this ADR does not redesign recovery queues, migrate
`transport_state`, add host telemetry, change SBE output, introduce new venues,
or claim live-feed completeness. Those changes require their own staged
acceptance evidence after S1a/S1b.

## 6. Follow-on order

After S1a/S1b are green, proceed with the existing feed-continuity sequence:

S2 — consolidate transport state only after all current write/read sites and
   consumers are enumerated;
M3.1 — introduce typed `RecoveryAction` and `RecoveryCause`;
3. M3.2 — separate instrument and source recovery queues;
4. M3.3 — scope acknowledgements and fences to exact instrument generations;
5. M4 — prove one-source and multi-replica recovery blast radius, including
   emitted SBE output;
6. M5/M6 — exercise a deterministic 4,000-instrument mixed hot/quiet workload
   and persist recovery/host evidence; and
7. M7 — run the full offline assurance gate and staged live validation.

No later phase may weaken a protected test or reinterpret a previously accepted
fence contract without a new ADR.
