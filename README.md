# a2a-transport-nostr

Nostr private messaging for a2a: NIP-17 rumors, NIP-44 v2 encryption,
NIP-59 seals/gift wraps, NIP-65/10050 routing, NIP-42 relay authentication
and Blossom encrypted media. The authenticated sender is the seal signer;
it must equal the rumor pubkey. The ephemeral wrapper is never identity.

## T0 adapter (provisional)

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

The new API follows the supplied T0 brief/addendum. Its **only provisional
production import** is `nostrtransport/seam_bridge.go` importing
`internal/seamprovisional`; package initialization registers `nostr`, with
any registration error exposed as `RegistrationError` rather than a panic.
The provisional runner is **not** evidence of upstream conformance. Replace
the bridge and runner with the landed upstream `transport` and
`transport/conformancetest`, pin its module version, delete the provisional
package and rerun all checks before final delivery. Upstream names and
contracts take precedence. No a2a-swarm source is changed here.

### Delivery and state

- `Send` validates before wire I/O, then durably persists the exact unsigned
  NIP-17 rumor, signed seals and every signed recipient/self wrap, pinned
  recipient routes and progress under the idempotency key. A transaction tag
  keeps different keys distinct even for identical text within one second.
- ACK requires an actual `OK true` for **every party including self** from
  one of its pinned routes. `OK true` with `duplicate:` counts; `OK false`
  with `duplicate:` remains UNKNOWN on this seam. The legacy API retains its
  earlier duplicate classification.
- Retries reuse the same rumor ID and byte-identical wraps and skip ACKed
  parties. Missing answers give UNKNOWN. Only closed `blocked:`, `invalid:`
  or `restricted:` original replies from every route of a party can prove
  REFUSED. Durable uncertainty before a publish is sticky: a later negative
  reply cannot prove an earlier lost-ACK attempt was never stored.
- State write uncertainty never yields a false ACK or triggers reconstruction
  of a lost/corrupt journal. A checksum, identity binding, signature checks
  and seal/rumor consistency detect malformed stored records. Corrupt send
  state gives UNKNOWN with no new publish; there is no automatic repair.
- Methods serialize operations per adapter. Disk ownership uses an OS file
  lock; process exit releases the lock, while persisted bytes survive.

### Sync, history and capabilities

- A versioned, identity-bound opaque cursor holds a local checkpoint, relay
  set and bounded verified wrap/rumor ID sets. A nonempty foreign, malformed
  or incomplete cursor is `invalid_cursor`, never reset to now.
- REQ filters event **created_at** from checkpoint minus 48 hours minus
  15 minutes skew. A wrap dated 47 hours before a checkpoint but published
  after it is delivered on resume. The checkpoint is bookkeeping, not a
  server receipt timestamp; claimed event time does not order delivery.
- `relay_unreachable`, `relay_set_changed`, `window_exceeded` and
  `timeline_limited` are the only gap reasons. An empty gap conversation
  means the whole identity inbox. A disconnected/limited relay cannot be
  represented as complete. A relay cannot prove that it returned every
  matching event. Events excluded by its timestamp filter are not observable;
  see `UNRESOLVED_QUESTIONS.md` for the explicit window bound.
- Verified events are persisted before returning a batch. The caller owns
  mailbox-before-cursor persistence. The adapter never substitutes an internal
  cursor on restart and silently skips a caller's uncommitted batch.
- History/Event use the same authenticated event cache and reverify its
  original wrap. History snapshots are bounded and fail closed when the
  cache/backlog cannot be covered; they are not an unbounded archive.
- Capabilities: per-conversation E2EE true, sender-side membership, threads,
  idempotent retry, no receipts and redaction None. The adapter implements
  no optional extension interfaces. Canonical addressing is lowercase hex
  public keys and canonical participant/subject JSON, built with
  `ConversationFor`; display names and Matrix shortcuts are not identities.
- Text budget is 4096 UTF-8 bytes with separately bounded metadata. Tests
  exercise exact-bound ASCII, backslash and control-byte escaping through
  both NIP-44 layers; bound+1 refuses before relay I/O. Actual serialization
  is also checked before discovery/publish. Conversations contain at most
  16 participants including self, with subjects up to 128 bytes.

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
- `internal/seamprovisional/`: disposable contract and group runner only.
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
go build -trimpath ./...
go run .scripts/check-guards.go -out .temp/controls-01
```

`.scripts/check-guards.go` copies this module into isolated `.temp/` fixtures,
plants one defect per run and invokes the corresponding assertion. Output
includes logs and `results.json` with source hashes, exits and expected failure
witnesses. Existing output paths are never overwritten. Compile/setup failures
are not detections. Tests cover valid neighbors, receipt loss, partial ACK,
restart, foreign/incomplete cursors, backdated publication, sender mismatch,
media secrecy, corrupt state and content bounds. The provisional runner's
fault hook that loses retry keys has its own bounded subprocess control.

## License

MIT — see `LICENSE`.
