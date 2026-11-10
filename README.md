# a2a-transport-nostr

Nostr private messaging for a2a: NIP-17 rumors, NIP-44 v2 encryption,
NIP-59 seals/gift wraps, NIP-65/10050 routing, NIP-42 relay authentication
and Blossom encrypted media. The authenticated sender is the seal signer;
it must equal the rumor pubkey. The ephemeral wrapper is never identity.

## Go module

The canonical module path is `github.com/relux-works/a2a-transport-nostr`.
Consumers import the adapter as:

```go
import "github.com/relux-works/a2a-transport-nostr/nostrtransport"
```

After the reviewed `v0.2.0` tag is published, add the dependency from the
consumer's module root:

```sh
go get github.com/relux-works/a2a-transport-nostr@v0.2.0
```

Use the published module directly, without a checkout-local `replace`. The
previous vanity module path is retired; it has no module-discovery service.
This path migration does not publish a release by itself or change the pinned
`github.com/relux-works/a2a-swarm/transport` dependency described below.

## T0 adapter

`nostrtransport.Open(SeamConfig)` creates one exclusive adapter from an
absolute, private `StateDir` and explicit settings. It generates or reloads
`identity.key` there; no environment or a2a configuration is read. Directory
modes are 0700, files 0600. Existing broad directories, symlink roots/keys,
missing keys in initialized roots, concurrent owners and legacy cursor
state refuse. Use a separate state root from the old prototype.

Settings are JSON arrays of URLs under `read_relays`, `write_relays`,
`dm_relays`, `discovery_relays`, and `blossom_servers`. At least one read or
write relay is required; defaults and authenticated discovery use the
existing routing implementation. No public relay is contacted by default.

The adapter imports `github.com/relux-works/a2a-swarm/transport` at
`v0.0.0-20261109151928-db64f2d1b23b`, exactly upstream commit
`db64f2d1b23b1d40db9a22c0c515a186a266638d`. The pseudo-version and `go.sum`
pin the source without a checkout-local replace. Package initialization
registers `nostr`; `RegistrationError` exposes a registration conflict without
panicking. The disposable provisional package has been deleted.

`TestUpstreamConformance` invokes that commit's unchanged `conformancetest.Run`.
The adapter passes T0 conformance at `db64f2d1b23b1d40db9a22c0c515a186a266638d`:
all 20 top-level groups, both addressing reference subgroups and
`raw_bounds/received` PASS with zero SKIPs against local fixtures.

`PrincipalReferences` supplies the actual B identity in canonical lowercase hex
and a genuine NIP-19 npub reference that this adapter must refuse.
`ConversationReferences` supplies the actual shared canonical participant JSON
and a grammar-invalid neighbor. Supplemental parser controls cover malformed
and uppercase keys, invalid curve points, noncanonical conversations and missing
self membership, beside valid references and with no relay I/O.

The harness uses local Nostr/Blossom servers, actual relay attempt counts,
a one-shot lost ACK, a failure before the third recipient's publish, definite
relay refusals, cancellation before submission, relay retention loss, and a
seal/rumor impersonation of an existing principal. No upstream source is patched.
`ReceivedRawAtSize` publishes a real authenticated A-to-B event of exactly the
requested serialized wire size, using signed outer padding through the ordinary
test relay. The adapter declares `Caps().MaxRawBytes = 0` and returns nil Raw
on every read path. The oversized event is rejected at the actual receive
boundary; no transport result, drop count or Raw is fabricated.

### Delivery and state

- `Send` validates before wire I/O, then durably persists the exact unsigned
  NIP-17 rumor, signed seals and every signed recipient/self wrap, pinned
  recipient routes and progress under the idempotency key. A transaction tag
  keeps different keys distinct even for identical text within one second.
- Explicit `To` restricts delivery to those recipients plus self, deduplicated;
  empty `To` addresses the whole conversation. Delivery starts with self, then
  explicit recipients in order.
- ACK requires an original relay response classified as stored for **every
  party including self** from one of its pinned routes: either `OK true` or
  `OK false` with a `duplicate:` reason. Both confirm the exact wrap ID under
  the same relay-trust assumption; no other `OK false` becomes an ACK.
  A lost-ACK retry reuses the stored wrap and accepts either duplicate form.
- Retries reuse the same rumor ID and byte-identical wraps and skip ACKed
  parties. Only ACK includes an EventID. Partial publication or missing answers
  give UNKNOWN without Event/Refusal. Only closed `blocked:`, `invalid:` or
  `restricted:` original replies from every route of every part, with no ACK
  or uncertainty, produce REFUSED and a closed upstream Refusal value. Durable uncertainty before a publish is sticky: a later negative
  reply cannot prove an earlier lost-ACK attempt was never stored.
- State write uncertainty never yields a false ACK or triggers reconstruction
  of a lost/corrupt journal. A checksum, identity binding, signature checks
  and seal/rumor consistency detect malformed stored records. Corrupt send
  state gives UNKNOWN with no new publish; there is no automatic repair.
- Methods serialize operations per adapter. Disk ownership uses an OS file
  lock; process exit releases the lock, while persisted bytes survive.

### Sync, history and capabilities

- A versioned, identity-bound opaque cursor holds a local checkpoint, relay
  set and bounded verified wrap/rumor ID sets. Empty cursors require
  `SyncOptions{Initial: true}`. A nonempty foreign, malformed
  or incomplete cursor is `invalid_cursor`, never reset to now.
- REQ filters event **created_at** from checkpoint minus 48 hours minus
  15 minutes skew. A wrap dated 47 hours before a checkpoint but published
  after it is delivered on resume. The checkpoint is bookkeeping, not a
  server receipt timestamp; claimed event time does not order delivery.
- `relay_unreachable`, `relay_set_changed`, `window_exceeded` and
  `timeline_limited` are the only gap reasons. An empty gap conversation
  means the whole identity inbox; previously verified conversations also
  receive a scoped gap when relay/window loss might affect them. A disconnected/limited relay cannot be
  represented as complete. A relay cannot prove that it returned every
  matching event. Events excluded by its timestamp filter are not observable;
  see `UNRESOLVED_QUESTIONS.md` for the explicit window bound.
- Verified events are persisted before returning a batch. The caller owns
  mailbox-before-cursor persistence. The adapter never substitutes an internal
  cursor on restart and silently skips a caller's uncommitted batch.
- History/Event use the same authenticated event cache and reverify its
  original wrap. Rejected incoming events increment `Batch.Dropped`; History
  exposes the count from its initial scan. `Event.Raw` is intentionally absent,
  avoiding accidental disclosure of private envelope material. The receive
  verifier separately bounds serialized wraps by upstream `MaxRawBytes`.
  History uses a typed `Cursor`; incomplete/foreign snapshots fail closed.
  History snapshots are bounded and fail closed when the
  cache/backlog cannot be covered; they are not an unbounded archive.
- Normal WebSocket messages remain limited to `relay.MaxFrameBytes` (256 KiB).
  Larger messages are streamed and discarded up to the inclusive
  `relay.MaxDrainBytes` ceiling: upstream `MaxRawBytes` (1 MiB) plus the fixed
  `DrainFramingAllowance` (64 KiB) for the NIP-01 envelope. This allowance never
  admits an oversized event. A recognizable EVENT prefix for the active query
  increments Dropped only after the entire oversized message is drained; its
  body is not authenticated or cached. The reader continues to later neighbors
  and EOSE, so one such event cannot poison repeated Sync/History scans.
- Drain retains a fixed 256 KiB + 1 byte prefix and uses 4 KiB scratch for the
  remainder, including fragmented WebSocket messages. It does not buffer the
  discarded body. Malformed/unattributable messages do not fabricate event
  counts. Above 1,114,112 total message bytes, or on an interrupted drain, the
  connection closes: Sync reports an honest `relay_unreachable` gap and History
  refuses with `unavailable`, without counting that incomplete frame as a drop.
  A relay repeatedly serving above-ceiling frames can still deny availability;
  this is an explicit resource bound. Query cancellation closes a stalled
  connection so its partial body cannot leak into the next query.
- Capabilities: per-conversation E2EE true, sender-side membership, threads,
  idempotent retry, no receipts, `MaxRawBytes: 0` and redaction NoRedaction. The adapter implements
  no optional extension interfaces. Canonical addressing is lowercase hex
  public keys and canonical participant/subject JSON, built with
  `ConversationFor`; display names and Matrix shortcuts are not identities.
- Removing the dedicated `swarma.grant.v1` extension must leave a serialized
  `wireMessage` JSON envelope of at most 4096 bytes, including escaped text,
  metadata, attachments and ordinary extensions. Ordinary extensions retain
  their aggregate 1024-byte serialized-object limit. These are byte limits,
  not character allowances. Only the dedicated grant field receives additional
  space in `Caps().MaxContentBytes`; other fields cannot borrow its allowance.
  `MessageAtSize` exercises the advertised maximum with a maximum-size grant.
  Both NIP-44 plaintext lengths and final relay framing are bounded before the
  first encryption/signature, route discovery or send journal write.
  Conversations contain at most 16 participants including self, with subjects
  up to 128 bytes. Receive/cache, relay, cursor and journal caps are unchanged.
- Operations honor cancellation and closed state with fixed `unavailable`
  errors; cancellation after a publication yields UNKNOWN and stops pending
  writes. Pure Caps/Addressing/Format remain usable after Close. Sync requests
  available events immediately (no long polling); EOSE/network waits have
  per-relay timeouts bounded by the call context.

### Typed grant carrier

`GrantPresentationV1` is an untrusted transport carrier: `v` must be 1,
`grant_id` must be 64 lowercase hex characters, and `bytes` contains canonical
padded standard base64 for 1 through 16384 decoded bytes. Use
`EncodeGrantPresentation` and insert its result under `GrantExtension` in
`Message.Extensions`; `DecodeGrantPresentation` checks shape and size. Duplicate,
unknown or missing fields, other versions, invalid IDs and malformed/noncanonical
base64 refuse. Only the exact reserved extension key gets the enlarged budget;
version-like neighbors remain ordinary extensions. Oversize values return
`content_too_large`; malformed carriers return `invalid_reference`.

The adapter does not parse certificates, verify a grant ID against its bytes,
admit a peer or cache an authorization verdict. Admission remains the caller's
responsibility using the authenticated seal sender. The carrier never moves
grant data into human-authored `Message.Text`. Inbound messages use the same
carrier and base-message checks after NIP-17 authentication; rejected events
are dropped without being cached. Older adapters may reject the new carrier
under their former 1024-byte extension limit; there is no capability negotiation
or silent truncation.

### Media

Upload encrypts with the existing AES-256-GCM helper and authorizes Blossom
upload using a kind-24242 event signed by the transport identity. MediaRef
carries an opaque private descriptor; formatting prints `MediaRef(redacted)`.
It never enters diagnostics or logs. Sending an attachment uses kind 15,
including its authenticated file tags inside the sealed rumor. One attachment
per message and 8 MiB plaintext per file are supported.

Download uses only explicitly configured Blossom servers by ciphertext hash,
not a received URL. It verifies ciphertext/plaintext hashes, nonce/key shape
and the caller's size limit before writing plaintext. Authentication errors,
server text and received references are mapped to fixed closed errors.

## Layout and compatibility

- `nostrtransport/adapter*.go`, `seam_bridge.go`: the new T0-facing adapter.
- `nostr/`: reviewed BIP-340/NIP-01/44/59/17 and encrypted-file primitives.
- `relay/`, `blossom/`: bounded wire clients; relay queries now return detached
  bounded results and distinguish original OK frames from local disconnects.
- `testrelay/`, `testblossom/`: loopback-only test servers and fault hooks.
- `transport/` and the original `nostrtransport.Transport`/`New`: the earlier
  prototype API, retained with its existing regression tests. Its old
  capabilities and cursor semantics are not the new seam's contract.

## Tools and checks

Go is the only implementation/test language. All tests use local relay and
Blossom servers; no mainnet, real wallet, live relay or deployment is needed.
Run from the module root with the pinned toolchain in CI:

```sh
test "$(go list -m)" = github.com/relux-works/a2a-transport-nostr
go mod verify
go vet ./...
go test -race -count=1 ./...
go test -count=1 ./nostrtransport -run '^TestUpstreamConformance$' -v
go build -trimpath ./...
go run .scripts/check-guards.go -out .temp/controls-01
```

CI checks the canonical module identity before downloading and verifying the
pinned dependencies. A different module path fails that step; its diagnostics
and the remaining checks appear in the CI job log.

`.scripts/check-guards.go` copies this module into isolated `.temp/` fixtures,
plants one defect per run and invokes the corresponding assertion. Output
includes logs and `results.json` with source hashes, exits and expected failure
witnesses. Existing output paths are never overwritten. Compile/setup failures
are not detections. Tests cover valid neighbors, receipt loss, partial ACK,
restart, foreign/incomplete cursors, backdated publication, sender mismatch,
media secrecy, corrupt state and content bounds. The two addressing hooks have removal and valid-for-both reference plants;
the Raw hook has removal, falsely small-event, nonzero-capability and Raw-exposure
plants. Receive controls disable draining, suppress relay/batch counters, inflate
scratch allocation and leave a cancelled drain open; each must fail its named
assertion. A generated input measures bounded helper allocations independently
of the local relay's fixture storage. The upstream runner's fault hook that loses retry keys has its own bounded
subprocess control.
Formatting is owned by the pinned upstream MediaRef type; local controls no
longer mutate its deleted provisional implementation. The log-disclosure
control still plants a real adapter log call. Guard logs belong under `.temp/`.

Grant tests cover the exact decoded bound (16385 bytes has the same base64
length as 16384), unchanged ordinary-extension bounds with and without grants,
signed inbound rejection with a valid neighbor, real nested NIP-17 delivery,
maximum metadata/file delivery and sender/recipient restart. Length prediction
is compared with actual NIP-44 encryption at padding transitions and neighbors.
Grant guard plants relax the decoded and ordinary bounds, accept duplicate
fields, or underestimate the second encryption layer; each must fail its named
assertion. These tests verify transport shape and persistence, not grant authority.

## License

MIT — see `LICENSE`.
