# Pending integration and explicit limits

## T0 qualification at db64f2d1

The adapter passes T0 conformance at upstream
`db64f2d1b23b1d40db9a22c0c515a186a266638d` with zero SKIPs in local fixtures.
The upstream runner is unchanged. Actual addressing references and the genuine
ReceivedRawAtSize hook exercise all 20 top-level groups and receive/addressing
subgroups. The former #416 integration gap is closed: Caps.MaxRawBytes is zero,
Raw stays nil, and the wire-size probe uses a signed authenticated event through
the real test relay. Review, hosted checks and landing remain separate gates.

The receive path retains its 256 KiB normal-message ceiling. Oversized messages
through 1 MiB + 64 KiB of NIP-01 framing allowance are streamed, discarded and
counted for the active subscription only after complete draining. The reader
retains a 256 KiB + 1 byte prefix plus 4 KiB scratch. Above that inclusive drain
ceiling, or on interruption, connection loss remains an honest gap, not a
completed drop. History refuses an incomplete scan; Event refuses the oversized
ID. A relay repeatedly sending above-ceiling messages can still deny service.
No Raw exposure or cache-size expansion is needed or claimed.

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
- Legacy APIs remain available separately with their existing API semantics;
  they share the bounded relay reader but do not expose its new drop telemetry;
  callers needing T0 guarantees must construct the new adapter.

- Provisional state is not silently migrated. Old journals for requests with
  explicit To may contain extra recipients under the old contract; incompatible
  records stay UNKNOWN without republishing. Previously accepted messages above
  the new serialized-content bound likewise are not silently reinterpreted.
