# Pending integration and explicit limits

## Required before final N2 delivery

Upstream T0 has not been supplied as a landed head. Replace the disposable
contract, bridge and runner with that exact upstream module, resolve its actual
API and run its real conformance suite. Current provisional checks cannot
substitute for that gate. Final independent review follows the integrated head.

## Declared v1 limits (not unresolved implementation promises)

- No optional extensions, NIP-29 rooms, receipts, native redaction, owner bypass,
  Courier policy, public-network deployment or implicit legacy-state migration.
- The receive window is checkpoint minus 48h minus 15m skew on `created_at`.
  An old cursor whose checkpoint is more than that window behind local now
  produces `window_exceeded`. A relay-returned verified wrap outside the queried
  window can also produce it. A newly published wrap dated 49h plus skew before
  checkpoint is normally filtered out by the relay: the client cannot detect
  it and cannot truthfully manufacture a gap for that unseen event.
- Relay completeness is not cryptographically provable. Query results, seen
  sets and history snapshots are finite (4096), batches are at most 1024, and
  overflow reports `timeline_limited` or refuses history rather than claiming
  completeness. With enough traffic inside one timestamp window, the bounded
  scan may remain limited until that window passes; no archival guarantee.
- The verified cache/send journal currently require operator-managed retention.
  No automatic garbage collection discards idempotency anchors. Cache history
  over 4096 files fails closed. Cursor dedup is bounded; the caller retains its
  own durable logical-event deduplication as required by the seam.
- One adapter serializes its operations, including bounded network waits.
  Local file-lock semantics are supported on the repository's Unix platforms;
  untrusted shared directories/network filesystems are not an isolation boundary.
- The canonical principal surface accepts lowercase 64-hex keys only. Friendly
  npub/display-name resolution is not claimed by this provisional adapter.
- Legacy APIs remain available separately and retain their prior behavior;
  callers needing T0 guarantees must construct the new adapter.
