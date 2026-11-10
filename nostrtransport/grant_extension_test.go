package nostrtransport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	seam "github.com/relux-works/a2a-swarm/transport"
	"github.com/relux-works/a2a-transport-nostr/nostr"
	"github.com/relux-works/a2a-transport-nostr/relay"
)

func grantFixture(n int) GrantPresentationV1 {
	return GrantPresentationV1{Version: 1, GrantID: strings.Repeat("a", 64), Bytes: bytes.Repeat([]byte{0xff}, n)}
}

// A real 16384-byte opaque proof survives encoding; 16385 bytes (which has the
// same base64 length) must fail the decoded bound, not merely a JSON size check.
func TestGrantDecodedBoundary(t *testing.T) {
	for _, n := range []int{1, 16383, 16384, 16385} {
		p := grantFixture(n)
		raw, e := EncodeGrantPresentation(p)
		if n > 16384 {
			if seam.Code(e) != "content_too_large" || raw != nil {
				t.Fatal("oversized decoded grant encoded")
			}
			raw, _ = json.Marshal(p) // bypass the encoder as an untrusted sender can
			got, e := DecodeGrantPresentation(raw)
			if seam.Code(e) != "content_too_large" || len(got.Bytes) != 0 {
				t.Fatal("oversized decoded grant accepted")
			}
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		got, e := DecodeGrantPresentation(raw)
		if e != nil || got.Version != 1 || got.GrantID != p.GrantID || !bytes.Equal(got.Bytes, p.Bytes) {
			t.Fatal("valid bounded grant changed", e)
		}
	}
}

// Exact field names, one occurrence each, version 1, lowercase ID and canonical
// padded base64 are required. A carrier's validity is not certificate admission.
func TestGrantMalformedCarrier(t *testing.T) {
	valid, e := EncodeGrantPresentation(grantFixture(1))
	if e != nil {
		t.Fatal(e)
	}
	s := string(valid)
	cases := map[string]string{
		"duplicate":       strings.Replace(s, `"v":1`, `"v":1,"v":1`, 1),
		"alias":           strings.Replace(s, `"grant_id"`, `"Grant_ID"`, 1),
		"unknown":         strings.Replace(s, `"v":1`, `"v":1,"extra":0`, 1),
		"version":         strings.Replace(s, `"v":1`, `"v":2`, 1),
		"missing":         strings.Replace(s, `"v":1,`, ``, 1),
		"null-version":    strings.Replace(s, `"v":1`, `"v":null`, 1),
		"uppercase-id":    strings.Replace(s, strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		"short-id":        strings.Replace(s, strings.Repeat("a", 64), "a", 1),
		"empty":           strings.Replace(s, `/w==`, ``, 1),
		"null-bytes":      strings.Replace(s, `"/w=="`, `null`, 1),
		"base64-padding":  strings.Replace(s, `/w==`, `/w`, 1),
		"base64-pad-bits": strings.Replace(s, `/w==`, `/x==`, 1),
		"base64-newline":  strings.Replace(s, `/w==`, `/w==\n`, 1),
		"trailing":        s + `{}`,
		"truncated":       s[:len(s)-1],
		"array":           `[]`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			got, e := DecodeGrantPresentation(json.RawMessage(raw))
			if seam.Code(e) != "invalid_reference" || len(got.Bytes) != 0 {
				t.Fatalf("malformed carrier accepted: %s", name)
			}
		})
	}
	if _, e = DecodeGrantPresentation(valid); e != nil {
		t.Fatal("valid carrier refused", e)
	}
}

func ordinaryAtSize(n int) json.RawMessage {
	return json.RawMessage(`"` + strings.Repeat("x", n-len(`{"ordinary":""}`)) + `"`)
}

// Ordinary extensions retain their aggregate 1024-byte cap with and without a
// maximum grant. Rejections leave relay calls, published wraps and send state unchanged.
func TestGrantSendBudgets(t *testing.T) {
	w := newSeamWorld(t)
	grant, e := EncodeGrantPresentation(grantFixture(16384))
	if e != nil {
		t.Fatal(e)
	}
	for _, withGrant := range []bool{false, true} {
		for _, n := range []int{1024, 1025} {
			key := fmt.Sprintf("ordinary-%t-%d", withGrant, n)
			m := Message{Text: "ordinary", Extensions: map[string]json.RawMessage{"ordinary": ordinaryAtSize(n)}}
			if withGrant {
				m.Extensions[GrantExtension] = grant
			}
			if n == 1025 {
				assertGrantSendRejected(t, w, key, m, "content_too_large")
			} else {
				r, e := w.a.Send(context.Background(), SendRequest{Conversation: w.conv, Message: m, IdempotencyKey: key})
				if e != nil || r.Outcome != ACK {
					t.Fatal("ordinary boundary refused", e)
				}
			}
		}
	}
	tooBig, _ := json.Marshal(grantFixture(16385))
	assertGrantSendRejected(t, w, "grant-over", Message{Extensions: map[string]json.RawMessage{GrantExtension: tooBig}}, "content_too_large")
	assertGrantSendRejected(t, w, "grant-neighbor", Message{Extensions: map[string]json.RawMessage{"swarma.grant.v2": grant}}, "content_too_large")
	assertGrantSendRejected(t, w, "grant-malformed", Message{Extensions: map[string]json.RawMessage{GrantExtension: json.RawMessage(`{"v":2}`)}}, "invalid_reference")
	assertGrantSendRejected(t, w, "text-over", Message{Text: messageAtSize(baseMaxContent).Text + "x", Extensions: map[string]json.RawMessage{GrantExtension: grant}}, "content_too_large")
}

func assertGrantSendRejected(t *testing.T, w *seamWorld, key string, m Message, code seam.ErrorCode) {
	t.Helper()
	calls, events := w.r.Calls(), len(w.r.Events())
	r, e := w.a.Send(context.Background(), SendRequest{Conversation: w.conv, Message: m, IdempotencyKey: key})
	if seam.Code(e) != code || r.Event != "" || calls != w.r.Calls() || events != len(w.r.Events()) {
		t.Fatal("invalid grant message reached wire or wrong refusal", key, e)
	}
	if _, e := os.Stat(filepath.Join(w.a.dir, "seam-send", sendFileName(key))); !os.IsNotExist(e) {
		t.Fatal("invalid grant message persisted send state", key)
	}
}

// The advertised maximum passes the real two-layer NIP17 path and persists
// under existing event/journal caps with all 16 recipient/self parts. Restart
// preserves proof bytes and ACK IDs.
func TestGrantMaximumRoundtripRestart(t *testing.T) {
	w := newSeamWorld(t)
	parties := []PrincipalID{PrincipalID(w.b.core.Identity()), PrincipalID(w.c.core.Identity())}
	for len(parties) < 15 {
		key, e := nostr.GeneratePrivKey()
		if e != nil {
			t.Fatal(e)
		}
		parties = append(parties, PrincipalID(key.PubKeyHex()))
	}
	var e error
	w.conv, e = w.a.ConversationFor(parties, "")
	if e != nil {
		t.Fatal(e)
	}
	m := messageAtSize(w.a.Caps().MaxContentBytes)
	encoded, _ := json.Marshal(wireMessage{Version: 1, Text: m.Text, Extensions: m.Extensions})
	if len(encoded) != w.a.Caps().MaxContentBytes {
		t.Fatal("maximum fixture is not exact")
	}
	req := SendRequest{Conversation: w.conv, Message: m, IdempotencyKey: "grant-max"}
	first, e := w.a.Send(context.Background(), req)
	if e != nil || first.Outcome != ACK {
		t.Fatal("maximum grant send failed", e)
	}
	var rec seamSend
	raw, e := readPrivate(filepath.Join(w.a.dir, "seam-send", sendFileName(req.IdempotencyKey)), 4<<20)
	if e != nil || json.Unmarshal(raw, &rec) != nil || len(rec.Parts) != 16 {
		t.Fatal("maximum journal unreadable", e)
	}
	for _, part := range rec.Parts {
		sealRaw, _ := json.Marshal(part.Seal)
		wrapRaw, _ := json.Marshal(part.Wrap)
		frame, _ := json.Marshal([]any{"EVENT", "fixture", part.Wrap})
		if len(sealRaw) > 65535 || len(wrapRaw) > maxRawBytes || len(frame) > relay.MaxFrameBytes {
			t.Fatal("maximum exceeds nested envelope limits")
		}
	}
	batch, e := w.b.Sync(context.Background(), nil, SyncOptions{Initial: true})
	if e != nil || len(batch.Events) != 1 || batch.Events[0].ID != first.Event {
		t.Fatal("maximum grant not received", e)
	}
	w.restartB(t)
	ev, e := w.b.Event(context.Background(), w.conv, first.Event)
	if e != nil || ev.Message.Text != m.Text || !bytes.Equal(ev.Message.Extensions[GrantExtension], m.Extensions[GrantExtension]) {
		t.Fatal("maximum grant changed after recipient restart", e)
	}
	proof, e := DecodeGrantPresentation(ev.Message.Extensions[GrantExtension])
	if e != nil || len(proof.Bytes) != 16384 {
		t.Fatal("maximum decoded proof lost", e)
	}
	w.a.Close()
	w.a, e = Open(w.configs[0])
	if e != nil {
		t.Fatal(e)
	}
	defer w.a.Close()
	calls := w.r.Calls()
	again, e := w.a.Send(context.Background(), req)
	if e != nil || again != first || calls != w.r.Calls() {
		t.Fatal("maximum grant retry changed ACK or republished", e)
	}
}

// Maximum participant/subject metadata and a file attachment coexist with both
// extension budgets. Escaped text fills the original 4096-byte message budget;
// the real nested encryption and receive cache must still carry all fields.
func TestGrantMetadataRoundtrip(t *testing.T) {
	w := newSeamWorld(t)
	parties := []PrincipalID{PrincipalID(w.b.core.Identity())}
	for len(parties) < 15 {
		key, e := nostr.GeneratePrivKey()
		if e != nil {
			t.Fatal(e)
		}
		parties = append(parties, PrincipalID(key.PubKeyHex()))
	}
	conv, e := w.a.ConversationFor(parties, strings.Repeat("s", 128))
	if e != nil {
		t.Fatal(e)
	}
	ref, e := w.a.Upload(context.Background(), strings.NewReader("fixture"), MediaMeta{Size: 7, ContentType: "text/plain"})
	if e != nil {
		t.Fatal(e)
	}
	m := Message{Kind: strings.Repeat("k", 64), To: parties[:1], Re: EventID(strings.Repeat("a", 64)), Thread: EventID(strings.Repeat("b", 64)), Attachments: []MediaRef{ref}, Extensions: map[string]json.RawMessage{"ordinary": ordinaryAtSize(1024)}}
	base, e := toWire(m)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(base)
	space := 4096 - len(raw)
	if space < 0 {
		t.Fatal("metadata fixture exceeds base budget")
	}
	m.Text = strings.Repeat("\x00", space/6) + strings.Repeat("x", space%6)
	grant, e := EncodeGrantPresentation(grantFixture(16384))
	if e != nil {
		t.Fatal(e)
	}
	m.Extensions[GrantExtension] = grant
	r, e := w.a.Send(context.Background(), SendRequest{Conversation: conv, Message: m, IdempotencyKey: "grant-metadata"})
	if e != nil || r.Outcome != ACK {
		t.Fatal("maximum grant metadata cannot be sent", e)
	}
	batch, e := w.b.Sync(context.Background(), nil, SyncOptions{Initial: true})
	if e != nil || len(batch.Events) != 1 || batch.Events[0].Conversation != conv {
		t.Fatal("grant metadata not received", e)
	}
	got := batch.Events[0].Message
	if got.Text != m.Text || got.Kind != m.Kind || got.Re != m.Re || got.Thread != m.Thread || len(got.Attachments) != 1 || !bytes.Equal(got.Extensions[GrantExtension], grant) || !bytes.Equal(got.Extensions["ordinary"], m.Extensions["ordinary"]) {
		t.Fatal("grant metadata changed")
	}
}

// An authenticated malicious sender cannot use the valid outer signatures to
// admit an oversized/invalid carrier. Sync drops it and caches only its valid neighbor.
func TestGrantInboundBoundary(t *testing.T) {
	w := newSeamWorld(t)
	c, _ := w.a.conversation(w.conv)
	var good EventID
	var bad []EventID
	for _, n := range []int{16384, 16385} {
		raw, _ := json.Marshal(grantFixture(n))
		body, _ := json.Marshal(wireMessage{Version: 1, Text: "peer", Extensions: map[string]json.RawMessage{GrantExtension: raw}})
		rumor, e := nostr.BuildRumor(w.a.core.cfg.Key, c.P, nostr.KindRumor, string(body), nostr.RumorOptions{}, time.Now().Unix())
		if e != nil {
			t.Fatal(e)
		}
		wrap, e := nostr.GiftWrap(rumor, w.a.core.cfg.Key, w.b.core.Identity(), time.Now().Unix())
		if e != nil {
			t.Fatal(e)
		}
		_, e = w.b.verifyWrap(wrap)
		if n == 16384 {
			if e != nil {
				t.Fatal("valid inbound grant refused", e)
			}
			good = EventID(rumor.ID)
		} else {
			if seam.Code(e) != "content_too_large" {
				t.Fatal("oversized inbound grant accepted", e)
			}
			bad = append(bad, EventID(rumor.ID))
		}
		client := &relay.Client{URL: w.r.URL}
		ok, e := client.Publish(context.Background(), wrap)
		client.Close()
		if e != nil || !ok.Accepted {
			t.Fatal("signed fixture publish failed", e)
		}
	}
	batch, e := w.b.Sync(context.Background(), nil, SyncOptions{Initial: true})
	if e != nil || len(batch.Events) != 1 || batch.Events[0].ID != good || batch.Dropped != 1 {
		t.Fatal("inbound grant drop lost neighbor or accounting", e)
	}
	for _, id := range bad {
		if _, e := os.Stat(filepath.Join(w.b.dir, "seam-events", string(id)+".json")); !os.IsNotExist(e) {
			t.Fatal("oversized inbound grant cached")
		}
	}
}

// Length-only preflight accepts a real nearby envelope and rejects an inner
// plaintext that fits NIP44 but whose encrypted seal cannot fit the second layer.
func TestGrantNestedPreflight(t *testing.T) {
	w := newSeamWorld(t)
	c, _ := w.a.conversation(w.conv)
	for _, n := range []int{26000, 50000, 65536} {
		r, e := nostr.BuildRumor(w.a.core.cfg.Key, c.P, nostr.KindRumor, strings.Repeat("x", n), nostr.RumorOptions{}, time.Now().Unix())
		if e != nil {
			t.Fatal(e)
		}
		e = preflightEnvelopeSize(r)
		if n == 26000 {
			if e != nil {
				t.Fatal("valid nested size refused", e)
			}
			if _, e = nostr.GiftWrap(r, w.a.core.cfg.Key, w.b.core.Identity(), time.Now().Unix()); e != nil {
				t.Fatal("accepted size cannot be encrypted", e)
			}
		} else if seam.Code(e) != "content_too_large" {
			t.Fatal("oversized nested envelope passed preflight", e)
		}
	}
}
