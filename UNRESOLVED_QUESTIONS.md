# Pending integration and explicit limits

## Upstream #381 and qualification limits

N2-02 binds actual landed T0 commit
`627be63050714d918fcb9fcfbaa348b70e0b104b` with no upstream modifications.
All 20 upstream groups pass locally. Independent review and maintainer-owned
hosted checks/landing remain separate gates.

The following observations concern `transport/conformancetest/conformance.go`
at that exact upstream commit. They are not adapter workarounds:

- `addressing` (line 573): the negative cases synthesize `invalid-<marker>`
  and `unknown-<marker>`. Both are invalid in this adapter's supported grammar
  (canonical lowercase 64-hex principal and participant/subject JSON), so no
  honest Nostr addressing case failed. This does not establish those strings
  are invalid for every external transport. Npub input is not claimed here.
- `raw_bounds` (line 722): checks lengths after a normal small message; there
  is no oversized-Raw injection hook. An implementation that only fails on
  large incoming events could pass. Nostr leaves Raw empty and separately
  tests a genuinely oversized, signed wrap at its receive verifier boundary;
  this does not strengthen the unchanged upstream group or claim live relay
  delivery of a >1 MiB frame (the relay client itself caps frames at 256 KiB).
- `unverifiable_sender` (line 447): the hook claims existing B; the group
  checks absence of the returned bad EventID and positive Dropped, beside one
  good ID. It does not reject a forged event with a different ID or verify the
  sender of every other event. Local `TestSeamImpersonationNeighbors` checks
  the whole delivery set, sender, marker and two existing-principal claims.
  That supplemental evidence is not an upstream #381 resolution.
- `outcome_discipline`'s pre-submit hook returns a context; this harness uses
  actual cancellation before any submission. It proves that concrete failure
  path, not every possible transient setup/transport failure. No marker-based
  special case or synthetic SendResult is used.

No upstream grammar failure was encountered. The first integration run failed
only the fixture root mode (Go TempDir used 0755); the fixture now creates its
owned root with 0700. No production permission rule was weakened.

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
  npub/display-name resolution is not claimed by this adapter.
- Legacy APIs remain available separately and retain their prior behavior;
  callers needing T0 guarantees must construct the new adapter.

- Provisional state is not silently migrated. Old journals for requests with
  explicit To may contain extra recipients under the old contract; incompatible
  records stay UNKNOWN without republishing. Previously accepted messages above
  the new serialized-content bound likewise are not silently reinterpreted.
