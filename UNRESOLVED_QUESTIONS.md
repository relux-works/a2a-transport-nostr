# Pending integration and explicit limits

## N3a partial qualification and upstream #416

N3a binds actual upstream commit
`0f73388cbc7ac3e719475a82c6f669e60851d116` with no upstream modifications.
All 20 top-level conformance groups and both addressing reference subgroups
pass locally. `raw_bounds/received` is the **one allowed explicit SKIP**,
pending upstream contract ruling integration (#416). Independent review,
maintainer-owned hosted checks and landing remain separate gates.

The addressing hooks now supply this adapter's real supported/unsupported
grammar rather than relying on upstream synthetic marker strings. The
principal hook supplies canonical B hex versus a genuine unsupported npub;
the conversation hook supplies canonical shared JSON versus invalid JSON.
The updated upstream unverifiable-sender group also rejects any delivered
event attributed to the claimed B, even when the forged event ID is rewritten.

At this exact pin, `ReceivedRawAtSize(MaxRawBytes)` must produce an authenticated
event with exactly 1 MiB of returned Raw on Sync, History and Event. This conflicts
with the adapter's intentional empty Raw projection and 256 KiB relay frame and
saved-event read ceilings. Padding an Event, bypassing the real relay, or changing
only test limits would not establish the requested behavior. The hook remains
nil and its skipped checks are unverified, never reported as passed. The existing
local oversized signed-wrap test exercises the receive verifier directly; it
makes no >1 MiB relay round-trip claim.

Upstream has ruled that Raw is optional and a lower transport-declared Raw
ceiling is allowed. Planned #416 adds `Caps.MaxRawBytes`: zero requires empty
Raw, positive values declare an exposed Raw bound. The wire ceiling remains a
separate limit. That API is not present at the pinned commit and is not assumed
by this adapter. Follow-up requires the landed upstream head and honest receive
controls under that contract before claiming zero SKIPs. No Raw exposure,
privacy-policy change or wire/cache limit expansion is authorized by N3a.

The pre-submit hook uses actual cancellation before submission. It proves that
concrete failure path, not all transient setup/transport failures. No
marker-based special case or synthetic SendResult is used.

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
