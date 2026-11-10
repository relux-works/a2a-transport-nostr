package nostrtransport

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"unicode/utf8"

	"github.com/relux-works/a2a-transport-nostr/internal/strictjson"
	"github.com/relux-works/a2a-transport-nostr/nostr"
	"github.com/relux-works/a2a-transport-nostr/relay"
)

const (
	// GrantExtension is a typed carrier, never an admission verdict. The
	// recipient must verify the certificate against the authenticated sender.
	GrantExtension = "swarma.grant.v1"
	// MaxGrantPresentationBytes matches CG1's decoded public-proof input cap.
	// The transport deliberately has no dependency on an admission policy.
	MaxGrantPresentationBytes = 16384
	maxOrdinaryExtensions     = 1024
	maxGrantExtensionJSON     = (MaxGrantPresentationBytes+2)/3*4 + len(`{"v":1,"grant_id":"`) + 64 + len(`","bytes":""}`)
	// Largest extra serialization cost: the base message has no extensions,
	// so adding this one field also introduces the extensions object itself.
	maxGrantWireOverhead = len(`,"extensions":{`) + len(GrantExtension) + 3 + maxGrantExtensionJSON + 1
)

// GrantPresentationV1 carries an untrusted certificate and its claimed ID.
// Bytes uses standard padded base64 in JSON. Neither field is a trusted sender
// identity; no certificate is parsed, admitted or cached by the transport.
type GrantPresentationV1 struct {
	Version int    `json:"v"`
	GrantID string `json:"grant_id"`
	Bytes   []byte `json:"bytes"`
}

// EncodeGrantPresentation produces the bounded typed extension value. Callers
// insert it under GrantExtension, separately from human-authored Message.Text.
func EncodeGrantPresentation(p GrantPresentationV1) (json.RawMessage, error) {
	if len(p.Bytes) > MaxGrantPresentationBytes {
		return nil, seamError("content_too_large")
	}
	if p.Version != 1 || !hexID(p.GrantID) || len(p.Bytes) == 0 {
		return nil, seamError("invalid_reference")
	}
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > maxGrantExtensionJSON {
		return nil, seamError("content_too_large")
	}
	return raw, nil
}

// DecodeGrantPresentation bounds allocation before decoding and refuses
// duplicate/unknown fields, aliases, unsupported versions and malformed base64.
// Success validates only the carrier's shape, never its authority.
func DecodeGrantPresentation(raw json.RawMessage) (GrantPresentationV1, error) {
	var p GrantPresentationV1
	if len(raw) > maxGrantExtensionJSON {
		return p, seamError("content_too_large")
	}
	if strictjson.Validate(raw) != nil {
		return p, seamError("invalid_reference")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, e := d.Token()
	if e != nil || token != json.Delim('{') {
		return p, seamError("invalid_reference")
	}
	seen := map[string]bool{}
	for d.More() {
		token, e = d.Token()
		key, ok := token.(string)
		if e != nil || !ok {
			return GrantPresentationV1{}, seamError("invalid_reference")
		}
		seen[key] = true
		switch key {
		case "v":
			e = d.Decode(&p.Version)
		case "grant_id":
			e = d.Decode(&p.GrantID)
		case "bytes":
			var encoded string
			e = d.Decode(&encoded)
			if e == nil {
				p.Bytes, e = base64.StdEncoding.Strict().DecodeString(encoded)
				if e == nil && base64.StdEncoding.EncodeToString(p.Bytes) != encoded {
					return GrantPresentationV1{}, seamError("invalid_reference")
				}
			}
		default:
			return GrantPresentationV1{}, seamError("invalid_reference")
		}
		if e != nil {
			return GrantPresentationV1{}, seamError("invalid_reference")
		}
	}
	if token, e = d.Token(); e != nil || token != json.Delim('}') || d.Decode(new(any)) != io.EOF || len(seen) != 3 {
		return GrantPresentationV1{}, seamError("invalid_reference")
	}
	if _, e = EncodeGrantPresentation(p); e != nil {
		return GrantPresentationV1{}, e
	}
	return p, nil
}

// Only the exact reserved key gets the grant budget. Every other key, including
// version-like neighbors, stays in the original aggregate 1024-byte budget.
func checkExtensions(ext map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	var ordinary map[string]json.RawMessage
	for k, raw := range ext {
		if len(k) > 128 || !utf8.ValidString(k) {
			return nil, seamError("invalid_reference")
		}
		if k == GrantExtension {
			if _, e := DecodeGrantPresentation(raw); e != nil {
				return nil, e
			}
			continue
		}
		if strictjson.Validate(raw) != nil {
			return nil, seamError("invalid_reference")
		}
		if ordinary == nil {
			ordinary = make(map[string]json.RawMessage)
		}
		ordinary[k] = raw
	}
	raw, e := json.Marshal(ordinary)
	if e != nil || len(raw) > maxOrdinaryExtensions {
		return nil, seamError("content_too_large")
	}
	if strictjson.Validate(raw) != nil {
		return nil, seamError("invalid_reference")
	}
	return ordinary, nil
}

// The fixed kind-13 and kind-1059 event metadata (IDs, keys, signatures, signed
// timestamps and the one recipient tag) each fit within 1024 serialized bytes.
// Base64 adds no JSON escaping. These conservative bounds include both NIP-44
// padding layers; the final event reserves the relay's full framing allowance.
// Only lengths of a real unsigned rumor are used; no synthetic event is sent.
func preflightEnvelopeSize(rumor *nostr.Event) error {
	raw, e := json.Marshal(rumor)
	if e != nil {
		return seamError("invalid_reference")
	}
	sealContent, e := nostr.NIP44PayloadSize(len(raw))
	if e != nil {
		return seamError("content_too_large")
	}
	wrapContent, e := nostr.NIP44PayloadSize(1024 + sealContent)
	if e != nil {
		return seamError("content_too_large")
	}
	wrapBound := 1024 + wrapContent
	if wrapBound > maxRawBytes || wrapBound+relay.DrainFramingAllowance > relay.MaxFrameBytes {
		return seamError("content_too_large")
	}
	return nil
}
