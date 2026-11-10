// Package nostr is a small, strict Nostr subset for private
// messaging transports: BIP-340 signatures, NIP-01 event ids,
// NIP-44 v2 encryption and NIP-59/NIP-17 gift-wrapped direct
// messages, on btcec/v2, with explicit validation at every layer
// so callers can refuse in a fixed order.
package nostr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/relux-works/a2a-transport-nostr/internal/strictjson"
)

// Event kinds used by this module.
const (
	KindSeal     = 13
	KindRumor    = 14 // NIP-17 chat message (unsigned inside a seal)
	KindGiftWrap = 1059
)

// Event is a NIP-01 event. PubKey and Sig are lowercase hex (x-only
// BIP-340 public key); ID is 64 lowercase hex chars.
type Event struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

// Serialize returns the NIP-01 id preimage:
// [0, pubkey, created_at, kind, tags, content] as compact JSON with
// Nostr string escaping (no HTML escaping).
func (e *Event) Serialize() []byte {
	dst := make([]byte, 0, 128+len(e.Content))
	dst = append(dst, "[0,\""...)
	dst = append(dst, e.PubKey...)
	dst = append(dst, "\","...)
	dst = strconv.AppendInt(dst, e.CreatedAt, 10)
	dst = append(dst, ',')
	dst = strconv.AppendInt(dst, int64(e.Kind), 10)
	dst = append(dst, ",["...)
	for i, tag := range e.Tags {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, '[')
		for j, s := range tag {
			if j > 0 {
				dst = append(dst, ',')
			}
			dst = escapeString(dst, s)
		}
		dst = append(dst, ']')
	}
	dst = append(dst, "],"...)
	dst = escapeString(dst, e.Content)
	dst = append(dst, ']')
	return dst
}

// escapeString appends s as a JSON string literal using the escaping
// Nostr requires for id computation: quote, backslash and the short
// control escapes, other control bytes as \u00XX, everything else raw.
func escapeString(dst []byte, s string) []byte {
	const hexd = "0123456789abcdef"
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			dst = append(dst, '\\', '"')
		case c == '\\':
			dst = append(dst, '\\', '\\')
		case c >= 0x20:
			dst = append(dst, c)
		case c == '\b':
			dst = append(dst, '\\', 'b')
		case c == '\t':
			dst = append(dst, '\\', 't')
		case c == '\n':
			dst = append(dst, '\\', 'n')
		case c == '\f':
			dst = append(dst, '\\', 'f')
		case c == '\r':
			dst = append(dst, '\\', 'r')
		default:
			dst = append(dst, '\\', 'u', '0', '0', hexd[c>>4], hexd[c&0x0f])
		}
	}
	return append(dst, '"')
}

// ComputeID returns the NIP-01 id (hex SHA-256 of Serialize).
func (e *Event) ComputeID() string {
	h := sha256.Sum256(e.Serialize())
	return hex.EncodeToString(h[:])
}

// CheckID reports whether e.ID equals the recomputed id.
func (e *Event) CheckID() bool {
	return len(e.ID) == 64 && e.ID == e.ComputeID()
}

// MarshalJSON emits the canonical field order used on relays.
func (e Event) MarshalJSON() ([]byte, error) {
	type wire struct {
		ID        string     `json:"id"`
		PubKey    string     `json:"pubkey"`
		CreatedAt int64      `json:"created_at"`
		Kind      int        `json:"kind"`
		Tags      [][]string `json:"tags"`
		Content   string     `json:"content"`
		Sig       string     `json:"sig"`
	}
	tags := e.Tags
	if tags == nil {
		tags = [][]string{}
	}
	return json.Marshal(wire{e.ID, e.PubKey, e.CreatedAt, e.Kind, tags, e.Content, e.Sig})
}

// ParseEvent refuses duplicate/escaped keys and exact-field aliases before
// signature processing. String values retain their ordinary JSON encoding.
func ParseEvent(raw []byte) (*Event, error) {
	var e Event
	if err := strictjson.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("event json: invalid shape")
	}
	if err := e.ValidateShape(); err != nil {
		return nil, err
	}
	return &e, nil
}

// ValidateShape checks field shapes only (lengths, hex, ranges). It does
// not verify id or signature; callers do that in their required order.
func (e *Event) ValidateShape() error {
	if !isLowerHex(e.ID, 64) && e.ID != "" {
		return fmt.Errorf("event id: want 64 lower hex or empty")
	}
	if !isLowerHex(e.PubKey, 64) {
		return fmt.Errorf("event pubkey: want 64 lower hex")
	}
	if !isLowerHex(e.Sig, 128) && e.Sig != "" {
		return fmt.Errorf("event sig: want 128 lower hex or empty")
	}
	if e.Kind < 0 || e.Kind > 65535 {
		return fmt.Errorf("event kind %d out of range", e.Kind)
	}
	if e.CreatedAt < 0 {
		return fmt.Errorf("event created_at %d negative", e.CreatedAt)
	}
	for _, tag := range e.Tags {
		if len(tag) == 0 {
			return fmt.Errorf("event tag: empty tag")
		}
	}
	return nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// TagFirst returns the first value of the first tag with the given name.
func (e *Event) TagFirst(name string) (string, bool) {
	for _, t := range e.Tags {
		if len(t) >= 2 && t[0] == name {
			return t[1], true
		}
	}
	return "", false
}
