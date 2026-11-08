# a2a-transport-nostr

A Nostr transport module behind the a2a transport interface:
private conversations over NIP-17 (kind 14 rumor, kind 13 seal,
kind 1059 gift wrap; NIP-44 v2, NIP-59), Blossom media
(BUD-01/02), NIP-65/NIP-50 (kind 10002/10050) relay routing and
NIP-42 relay authentication. The verified sender is always the
inner seal key, never the gift-wrap key.

## Layout

- `transport/` — the provisional interface package (local copy).
  It will be replaced by the upstream seam package when that
  lands; everything transport-specific stays behind it.
- `nostr/` — strict Nostr subset: BIP-340, NIP-01 ids, NIP-44 v2,
  NIP-59/NIP-17 (incl. small groups, kind 15 files), NIP-10
  markers, kind 5/10002/10050/22242/24242 builders.
- `relay/` — relay client: publish with OK classification
  (accepted / duplicate / rejected), subscriptions, NIP-42 AUTH.
- `blossom/` — Blossom client (hash-verified downloads).
- `nostrtransport/` — the Transport implementation.
- `testrelay/`, `testblossom/` — in-process loopback servers for
  conformance tests. Nothing in this repo contacts a real relay
  unless an embedder configures one.

## Semantics

- **Message id** is the rumor id: stable across recipients and
  gift wraps. `ConversationID` and `Cursor` are opaque bytes.
- **Send** persists the signed rumor and one wrap per recipient
  (fsync) before the first publish under the caller's idempotency
  key. A retry re-publishes byte-identical events; relays answer
  `duplicate:`, which counts as ACK like acceptance. Timeout or a
  non-duplicate refusal is UNKNOWN. ACK requires the configured
  quorum (default 1) per wrap. A different payload under a used
  idempotency key is a conflict.
- **Sync cursor** is (newest wrap time, bounded seen-id sets),
  queried with a skew window of 48h+300s by default (NIP-59 wraps
  are timestamp-jittered up to 2 days into the past). The cursor is
  persisted in the state directory, so restarts do not redeliver.
  Far-future events (beyond now+900s) are refused.
- **Routing:** recipients are reached via their kind 10050 DM
  relays, else kind 10002 write relays, else the configured
  fallback set. `PublishRelayLists` advertises the own lists.
- **Media:** public blobs are sha256-addressed via Blossom;
  private files are AES-256-GCM ciphertext blobs referenced by a
  kind 15 message carrying the key inside the sealed rumor. Both
  ciphertext and plaintext hashes are verified on fetch.
- **Redaction** is a kind 5 deletion request plus a local
  tombstone: best effort, never a guarantee.
- **Capabilities:** E2EE true, redaction best_effort, receipts
  false, membership sender-side (the participant set).

## Build and test

```sh
go vet ./...
go test -race ./...
go build -trimpath ./...
```

All tests run against loopback servers only. Official NIP-44 v2
and BIP-340 test vectors ship with the `nostr` package.

## License

MIT — see `LICENSE`.
