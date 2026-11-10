# SJ1: JSON keys on transport paths

SJ1 rejects ambiguous object keys before interpreting the object. It does not
normalize signed inputs or decide whether a grant is authorized. Presentation
bytes in `swarma.grant.presentation.v1` remain opaque; the receiving authority
validator must validate those bytes independently.

## Rule and limits

`internal/strictjson.Validate` walks the complete original UTF-8 JSON value,
including objects inside arrays and `json.RawMessage` values. Each object key
must occur once, with no JSON escape in its spelling. Both duplicate orderings,
escaped duplicates and escaped single keys are refused. Trailing values,
invalid UTF-8, input larger than 8 MiB and nesting beyond 64 edges are refused.
Existing smaller carrier, frame, content and reference limits still apply.
Ordinary string **values** may use legal JSON escapes and whitespace is legal.

`strictjson.Unmarshal` additionally checks exact struct field names, including
structs reached through map values, before decoding. It closes `encoding/json`'s
case-insensitive field aliases. Map keys remain case-sensitive application data;
`A` and `a` in an ordinary opaque object are distinct keys. Nullable legacy
slices/maps retain their prior behavior. Required fields, nullability and semantic
validation remain the caller's responsibility. The helper is for this module's
simple wire structs, not a general reflection decoder with embedded-field or
custom-unmarshaler schema support. Errors contain no input keys or values.

For outgoing extensions supplied as Go maps, check both the raw values and the
serialized map before any signing/persistence. Names requiring escaped spelling
in the module's JSON encoding are refused. Incoming original bytes are checked
before they can collapse into a map. No canonical re-encoding is used to repair
an ambiguous input, and NIP-01 signing serialization is unchanged.

## Decoder inventory

| Ingress | Guard and subsequent policy |
| --- | --- |
| Relay EVENT wrapper; decrypted NIP-59 seal and rumor (`nostr.ParseEvent`) | Shared lexical/exact-field decoder, then event shape; the existing callers verify IDs/signatures and authenticated sender relationships. |
| Adapter decrypted wire envelope and extensions (`verifyWrap`) | `strictJSON` covers the entire envelope including opaque extension subtrees before delivery/cache/verified seen IDs. |
| Standalone grant carrier (`DecodeGrantPresentation`) | Shared lexical guard, then exact version/field/base64/decoded-size checks; no authority admission. |
| Outgoing ordinary extensions (`checkExtensions`, `toWire`) | Shared lexical guard before hashes, signing, journal creation or publish. Grant carrier uses the standalone decoder. |
| Persisted adapter send/receive records, cursors, history cursors, media references and conversation IDs | Existing `strictJSON` call sites now use the shared lexical/exact-field guard before existing checksums, identity, canonical reference and shape policies. |
| Legacy `store.loadSend` and `store.loadCursor` | `strictJSON`; corrupt reads leave persisted bytes unchanged. Nullable legacy arrays remain accepted. |
| Legacy explicit cursor and conversation ID | `strictJSON` before state selection or participant interpretation. |
| Legacy `publishRecord` | Every persisted recipient wrap passes `nostr.ParseEvent` before the first publish or progress write; no partial publish due to a corrupt later JSON object. |

Remaining plain JSON decodes are not alternate authority-object decoders:
relay frame arrays/scalars retain each EVENT as original `RawMessage` for
`ParseEvent`; configured relay/Blossom URL arrays contain strings. Blossom upload
response descriptors are informational, not grants; media integrity remains
hash/authenticated-encryption based. The shared guard's internal map projections
run only after the lexical pass. Local test-relay filters are fixtures.

The adapter may increment drop telemetry and advance scan/checkpoint bookkeeping
when refusing inbound traffic. It does not admit the refused event, cache its
payload or add its verified wrap/rumor ID. This is distinct from promising that
no counter anywhere changes. Legacy resend still uses its existing signature,
routing and ACK policy; SJ1 adds JSON validation, not a new persistent-record
trust model.

## Evidence and controls

Run the normal race suite and the SJ1 controls in a disposable checkout with
absolute physical HOME/cwd, caches, configuration and temp paths under one owned
scratch root. No live relay, wallet, grant consumer or host installation is used.
The output directory must be new and absolute:

```sh
go test -race -count=1 ./...
go run .scripts/sj1-guards.go -out "$(pwd -P)/.temp/sj1-controls-01"
```

Tests pair duplicate orderings and escaped spellings with valid neighbors,
including an independently published signed NIP-01 event with whitespace and
escaped string values. Inner-object tests encrypt malformed seal/rumor JSON
under genuine keys and sign valid enclosing events. Adapter tests use the real
loopback relay and encrypted path, checking no invalid delivery/cache/seen IDs.
Outgoing and durable retry tests check relay call counts and journal bytes.
Legacy batch tests put the corrupt recipient last and require zero publishes;
repairing the batch must publish successfully.

The overlay control runner records a passing unmodified baseline for each
plant, source/mutant hashes, child PIDs, exits and logs. It disables duplicate,
escape, typed-map, event, envelope, carrier and durable-read guards and moves
batch validation back into the publish loop. Only the intended assertion failure
counts: compilation failure, panic, missing plant or timeout fails calibration.
Existing `.scripts/check-guards.go` controls remain supported; its carrier plant
now bypasses the shared lexical entry instead of the removed redundant duplicate
check, and fixture copies include `internal/`.
