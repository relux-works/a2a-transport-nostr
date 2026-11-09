# a2a-transport-nostr

Nostr private messaging for a2a: NIP-17 rumors, NIP-44 v2 encryption,
NIP-59 seals/gift wraps, NIP-65/10050 routing, NIP-42 relay authentication
and Blossom encrypted media. The authenticated sender is the seal signer;
it must equal the rumor pubkey. The ephemeral wrapper is never identity.

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
`v0.0.0-20261109134727-0f73388cbc7a`, exactly upstream commit
`0f73388cbc7ac3e719475a82c6f669e60851d116`. The pseudo-version and `go.sum`
pin the source without a checkout-local replace. Package initialization
registers `nostr`; `RegistrationError` exposes a registration conflict without
panicking. The disposable provisional package has been deleted.

`TestUpstreamConformance` invokes that commit's unchanged `conformancetest.Run`.
At `0f73388cbc7ac3e719475a82c6f669e60851d116`, all 20 top-level groups and both
addressing reference subgroups PASS. There is exactly one explicit SKIP:
**`raw_bounds/received` — pending upstream contract ruling integration (#416)**.
This is partial qualification, not an unqualified T0 conformance claim.

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
`ReceivedRawAtSize` remains nil because the pinned group requires exactly 1 MiB
of returned Raw, while this adapter intentionally omits Raw and uses a 256 KiB
wire/cache ceiling. Upstream has ruled that Raw is optional; #416's contract
implementation and a successor pin are pending. No Raw fabrication or size-limit
change is used to make this run pass. See `UNRESOLVED_QUESTIONS.md`.

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
- Capabilities: per-conversation E2EE true, sender-side membership, threads,
  idempotent retry, no receipts and redaction NoRedaction. The adapter implements
  no optional extension interfaces. Canonical addressing is lowercase hex
  public keys and canonical participant/subject JSON, built with
  `ConversationFor`; display names and Matrix shortcuts are not identities.
- The 4096-byte content budget counts the serialized inner `wireMessage` JSON
  envelope, including escaped text and all metadata/attachments/extensions.
  It is not a 4096-character text allowance. `MessageAtSize` measures that
  encoding; exact-bound and bound+1 neighbors exercise it. Outer NIP-44/59
  encryption layers are additionally checked against their protocol limits
  before discovery/publication. Conversations contain at most 16 participants
  including self, with subjects up to 128 bytes.
- Operations honor cancellation and closed state with fixed `unavailable`
  errors; cancellation after a publication yields UNKNOWN and stops pending
  writes. Pure Caps/Addressing/Format remain usable after Close. Sync requests
  available events immediately (no long polling); EOSE/network waits have
  per-relay timeouts bounded by the call context.

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
go mod verify
go vet ./...
go test -race -count=1 ./...
go test -count=1 ./nostrtransport -run '^TestUpstreamConformance$' -v
go build -trimpath ./...
go run .scripts/check-guards.go -out .temp/controls-01
```

`.scripts/check-guards.go` copies this module into isolated `.temp/` fixtures,
plants one defect per run and invokes the corresponding assertion. Output
includes logs and `results.json` with source hashes, exits and expected failure
witnesses. Existing output paths are never overwritten. Compile/setup failures
are not detections. Tests cover valid neighbors, receipt loss, partial ACK,
restart, foreign/incomplete cursors, backdated publication, sender mismatch,
media secrecy, corrupt state and content bounds. The two addressing hooks have removal and valid-for-both reference plants;
the upstream runner's fault hook that loses retry keys has its own bounded
subprocess control.
Formatting is owned by the pinned upstream MediaRef type; local controls no
longer mutate its deleted provisional implementation. The log-disclosure
control still plants a real adapter log call. Guard logs belong under `.temp/`.

## License

MIT — see `LICENSE`.
