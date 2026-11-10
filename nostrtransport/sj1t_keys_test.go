package nostrtransport

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	seam "github.com/relux-works/a2a-swarm/transport"
)

// HTML-sensitive map keys and raw nested keys survive genuine encrypted send,
// both rumor kinds, receive persistence/restart, and idempotent sender restart.
// Hashes retain the pre-SJ1T JSON encoding used by existing retry records.
func TestSJ1TKeyRoundTrip(t *testing.T) {
	for _, file := range []bool{false, true} {
		name := "text"
		if file {
			name = "file"
		}
		t.Run(name, func(t *testing.T) {
			w := newSeamWorld(t)
			ctx := context.Background()
			const key = "<tag>&"
			value := json.RawMessage(`{"<nested>&":"literal \\u003c and <>&"}`)
			req := SendRequest{Conversation: w.conv, IdempotencyKey: "sj1t", Message: Message{Text: "<>&", Extensions: map[string]json.RawMessage{key: value}}}
			if file {
				ref, e := w.a.Upload(ctx, bytes.NewBufferString("file"), MediaMeta{Size: 4, ContentType: "text/plain"})
				if e != nil {
					t.Fatal(e)
				}
				req.Message.Attachments = []MediaRef{ref}
			}
			sent, e := w.a.Send(ctx, req)
			if e != nil || sent.Outcome != ACK {
				t.Fatal("SJ1T legal key send refused", e)
			}
			raw, e := os.ReadFile(filepath.Join(w.a.dir, "seam-send", sendFileName(req.IdempotencyKey)))
			if e != nil {
				t.Fatal(e)
			}
			var rec seamSend
			if e := strictJSON(raw, &rec); e != nil {
				t.Fatal(e)
			}
			body := rec.Rumor.Content
			if file {
				body, _ = rec.Rumor.TagFirst("a2a-message")
			}
			if !bytes.Contains([]byte(body), []byte(`"<tag>&":`)) || !bytes.Contains([]byte(body), []byte(`"<nested>&":`)) {
				t.Fatal("SJ1T wire key escaped")
			}
			wire, e := toWire(req.Message)
			if e != nil {
				t.Fatal(e)
			}
			oldCanonical, _ := json.Marshal(struct {
				Conversation ConversationID
				Message      wireMessage
			}{req.Conversation, wire})
			if rec.Hash != digest(oldCanonical) {
				t.Fatal("SJ1T changed retry hash encoding")
			}
			batch, e := w.b.Sync(ctx, nil, SyncOptions{Initial: true})
			if e != nil || len(batch.Events) != 1 || batch.Dropped != 0 || batch.Events[0].ID != sent.Event {
				t.Fatal("SJ1T legal key delivery lost", e)
			}
			assertMessage := func(m Message) {
				t.Helper()
				if m.Text != req.Message.Text || !bytes.Equal(m.Extensions[key], value) || len(m.Attachments) != len(req.Message.Attachments) {
					t.Fatal("SJ1T extension or message changed")
				}
			}
			assertMessage(batch.Events[0].Message)
			w.restartB(t)
			// Direct cache load prevents Event's relay fallback from hiding a corrupt cache.
			cached, e := w.b.loadEvent(sent.Event)
			if e != nil {
				t.Fatal("SJ1T cache key escaped", e)
			}
			assertMessage(fromWire(cached.Message))
			w.a.Close()
			w.a, e = Open(w.configs[0])
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { w.a.Close() })
			calls := w.r.Calls()
			again, e := w.a.Send(ctx, req)
			if e != nil || again.Outcome != ACK || again.Event != sent.Event || w.r.Calls() != calls {
				t.Fatal("SJ1T retry changed identity or republished", e)
			}
			after, e := os.ReadFile(filepath.Join(w.a.dir, "seam-send", sendFileName(req.IdempotencyKey)))
			if e != nil || !bytes.Equal(raw, after) {
				t.Fatal("SJ1T retry changed journal", e)
			}
		})
	}
}

// Keys needing mandatory string escapes remain refused before relay/journal
// effects. This includes Go's unconditional U+2028/U+2029 map-key escaping.
func TestSJ1TUnencodableKeys(t *testing.T) {
	w := newSeamWorld(t)
	for _, key := range []string{"\u2028", "\u2029", "quote\"", "slash\\", "line\n", "\x00"} {
		req := SendRequest{Conversation: w.conv, IdempotencyKey: "sj1t-refused", Message: Message{Text: "test", Extensions: map[string]json.RawMessage{key: json.RawMessage(`1`)}}}
		calls := w.r.Calls()
		got, e := w.a.Send(context.Background(), req)
		if seam.Code(e) != "invalid_reference" || got.Outcome == ACK {
			t.Fatal("SJ1T unencodable key admitted", e)
		}
		if w.r.Calls() != calls {
			t.Fatal("refused key called relay")
		}
		if _, e := os.Stat(filepath.Join(w.a.dir, "seam-send", sendFileName(req.IdempotencyKey))); !os.IsNotExist(e) {
			t.Fatal("refused key journaled")
		}
	}
}

// The ordinary-extension limit counts compact raw-key JSON bytes, without the
// Encoder newline or HTML expansion; one extra byte is the intended rejection.
func TestSJ1TKeyBudget(t *testing.T) {
	for _, extra := range []int{0, 1} {
		value := json.RawMessage(`"` + strings.Repeat("x", maxOrdinaryExtensions-10+extra) + `"`)
		got, e := checkExtensions(map[string]json.RawMessage{"<>&": value})
		if extra == 0 {
			if e != nil || !bytes.Equal(got["<>&"], value) {
				t.Fatal("SJ1T exact key budget refused", e)
			}
		} else if seam.Code(e) != "content_too_large" || got != nil {
			t.Fatal("SJ1T key budget overflow admitted", e)
		}
	}
}
