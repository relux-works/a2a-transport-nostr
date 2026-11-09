// Package conformancetest is a disposable runner for the supplied T0 group list.
// It is not upstream conformance evidence; replace this package on T0 landing.
package conformancetest

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	seam "relux.works/a2a-transport-nostr/internal/seamprovisional"
	"strings"
	"testing"
	"time"
)

type Harness struct{ New func(*testing.T) *World }
type World struct {
	Oversize     seam.Message
	Foreign      seam.Cursor
	Advance      func(time.Duration)
	A, B         seam.Transport
	Conversation seam.ConversationID
	// All hooks are mandatory; faults operate on the test server/fixture only.
	Fault     func(string) func()
	Inject    func(string) seam.EventID
	Restart   func() seam.Transport
	Calls     func() int
	Dropped   func() uint64
	Logs      func() string
	StateDirs []string
	Sentinel  string
}

func setup(t *testing.T, h Harness) *World {
	t.Helper()
	if h.New == nil {
		t.Fatal("harness missing fault hook New")
	}
	w := h.New(t)
	for name, ok := range map[string]bool{"fault": w.Fault != nil, "inject": w.Inject != nil, "restart": w.Restart != nil, "wire calls": w.Calls != nil, "dropped": w.Dropped != nil, "logs": w.Logs != nil, "advance": w.Advance != nil} {
		if !ok {
			t.Fatalf("harness missing fault hook %s", name)
		}
	}
	return w
}
func send(t *testing.T, w *World, key, text string) seam.SendResult {
	t.Helper()
	r, e := w.A.Send(context.Background(), seam.SendRequest{Conversation: w.Conversation, Message: seam.Message{Text: text}, IdempotencyKey: key})
	if e != nil {
		t.Fatal("send failed", e)
	}
	return r
}
func sync(t *testing.T, b seam.Transport, c seam.Cursor) seam.Batch {
	t.Helper()
	r, e := b.Sync(context.Background(), c, seam.SyncOptions{})
	if e != nil {
		t.Fatal("sync failed", e)
	}
	for _, g := range r.Gaps {
		switch g.Reason {
		case "timeline_limited", "relay_unreachable", "relay_set_changed", "window_exceeded":
		default:
			t.Fatal("unclosed gap")
		}
	}
	return r
}

// Run checks the supplied brief/addendum contracts with real local transports.
func Run(t *testing.T, h Harness) {
	t.Run("stable_self_delivery", func(t *testing.T) {
		w := setup(t, h)
		a, e := w.A.Self(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		again, _ := w.A.Self(context.Background())
		if a.ID == "" || a.ID != again.ID {
			t.Fatal("self unstable")
		}
		r := send(t, w, "one", "hello")
		b := sync(t, w.B, nil)
		if r.Outcome != seam.ACK || r.Event == "" || len(b.Events) != 1 || b.Events[0].ID != r.Event || b.Events[0].Sender != a.ID {
			t.Fatal("verified sender delivery failed")
		}
	})
	t.Run("idempotent_retry", func(t *testing.T) {
		w := setup(t, h)
		one := send(t, w, "same", "hello")
		w.Advance(2 * time.Second)
		two := send(t, w, "same", "hello")
		b := sync(t, w.B, nil)
		if one.Outcome != seam.ACK || two.Outcome != seam.ACK || one.Event != two.Event || len(b.Events) != 1 {
			t.Fatal("idempotency key retry changed logical event")
		}
	})
	t.Run("restart_cursor_history", func(t *testing.T) {
		w := setup(t, h)
		one := send(t, w, "one", "first")
		b := sync(t, w.B, nil)
		w.B = w.Restart()
		two := send(t, w, "two", "second")
		next := sync(t, w.B, b.Next)
		if len(next.Events) != 1 || next.Events[0].ID != two.Event {
			t.Fatal("restart lost or duplicated events")
		}
		p, e := w.B.History(context.Background(), w.Conversation, nil, 1)
		if e != nil {
			t.Fatal(e)
		}
		all := map[seam.EventID]bool{}
		for {
			for _, v := range p.Events {
				all[v.ID] = true
			}
			if len(p.Next) == 0 {
				break
			}
			p, e = w.B.History(context.Background(), w.Conversation, p.Next, 1)
			if e != nil {
				t.Fatal(e)
			}
		}
		if len(all) != 2 || !all[one.Event] || !all[two.Event] {
			t.Fatal("history disagrees with Sync")
		}
	})
	t.Run("unknown_after_submit", func(t *testing.T) {
		w := setup(t, h)
		restore := w.Fault("fail-after-submit")
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		r, e := w.A.Send(ctx, seam.SendRequest{Conversation: w.Conversation, Message: seam.Message{Text: "uncertain"}, IdempotencyKey: "unknown"})
		cancel()
		restore()
		if e != nil || r.Outcome != seam.UNKNOWN {
			t.Fatal("submitted timeout is not UNKNOWN")
		}
		two := send(t, w, "unknown", "uncertain")
		b := sync(t, w.B, nil)
		if two.Outcome != seam.ACK || r.Event != two.Event || len(b.Events) != 1 {
			t.Fatal("unknown retry duplicated/lost event")
		}
	})
	t.Run("partial_ack", func(t *testing.T) {
		w := setup(t, h)
		restore := w.Fault("partial-ack")
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		r, e := w.A.Send(ctx, seam.SendRequest{Conversation: w.Conversation, Message: seam.Message{Text: "partial"}, IdempotencyKey: "partial"})
		cancel()
		restore()
		if e != nil || r.Outcome != seam.UNKNOWN {
			t.Fatal("partial delivery falsely ACKed")
		}
		two := send(t, w, "partial", "partial")
		b := sync(t, w.B, nil)
		if two.Outcome != seam.ACK || two.Event != r.Event || len(b.Events) != 1 {
			t.Fatal("partial retry lost idempotency")
		}
	})
	t.Run("content_bound", func(t *testing.T) {
		w := setup(t, h)
		restore := w.Fault("oversize")
		defer restore()
		n := w.A.Caps().MaxContentBytes
		if n <= 0 {
			t.Fatal("nonpositive content bound")
		}
		if send(t, w, "bound", strings.Repeat("x", n)).Outcome != seam.ACK {
			t.Fatal("exact bound refused")
		}
		calls := w.Calls()
		_, e := w.A.Send(context.Background(), seam.SendRequest{Conversation: w.Conversation, Message: w.Oversize, IdempotencyKey: "over"})
		if seam.Code(e) != "content_too_large" || w.Calls() != calls {
			t.Fatal("oversize reached wire or wrong rejection")
		}
	})
	t.Run("unverifiable_sender", func(t *testing.T) {
		w := setup(t, h)
		before := w.Dropped()
		w.Inject("unverifiable-sender")
		send(t, w, "neighbor", "valid")
		b := sync(t, w.B, nil)
		if len(b.Events) != 1 || b.Events[0].Message.Text != "valid" || w.Dropped() <= before {
			t.Fatal("unverifiable sender delivered or not counted")
		}
	})
	t.Run("backdated_publish", func(t *testing.T) {
		w := setup(t, h)
		b := sync(t, w.B, nil)
		id := w.Inject("backdated-publish")
		next := sync(t, w.B, b.Next)
		if len(next.Events) != 1 || next.Events[0].ID != id {
			t.Fatal("backdated event lost after checkpoint")
		}
	})
	t.Run("foreign_cursor", func(t *testing.T) {
		w := setup(t, h)
		b := sync(t, w.B, nil)
		restore := w.Fault("foreign-cursor")
		defer restore()
		calls := w.Calls()
		_, e := w.A.Sync(context.Background(), w.Foreign, seam.SyncOptions{})
		if seam.Code(e) != "invalid_cursor" || w.Calls() != calls {
			t.Fatal("foreign cursor reset or used on wire")
		}
		if _, e = w.B.Sync(context.Background(), b.Next, seam.SyncOptions{}); e != nil {
			t.Fatal("valid cursor neighbor refused")
		}
	})
	t.Run("unsupported_extension", func(t *testing.T) {
		w := setup(t, h)
		calls := w.Calls()
		_, ok := w.A.(interface {
			Redact(context.Context, seam.ConversationID, seam.EventID, string) (seam.SendResult, error)
		})
		var e error
		if !ok {
			e = seam.NewError("unsupported_by_transport")
		}
		if ok || seam.Code(e) != "unsupported_by_transport" || w.Calls() != calls {
			t.Fatal("optional extension unexpectedly implemented")
		}
	})
	t.Run("media_privacy", func(t *testing.T) {
		w := setup(t, h)
		data := []byte("private roundtrip")
		ref, e := w.A.Upload(context.Background(), bytes.NewReader(data), seam.MediaMeta{Size: int64(len(data)), ContentType: "text/plain"})
		if e != nil {
			t.Fatal(e)
		}
		var out bytes.Buffer
		meta, e := w.B.Download(context.Background(), ref, &out, 1024)
		if e != nil || !bytes.Equal(out.Bytes(), data) || meta.SHA256 == "" {
			t.Fatal("media hash roundtrip failed")
		}
		marker := "MEDIA-MARKER-DO-NOT-LOG"
		bad := seam.NewMediaRef([]byte(marker))
		_, e = w.B.Download(context.Background(), bad, &out, 1024)
		if e == nil || strings.Contains(fmt.Sprintf("%v %+v %#v %s %q %x %v %s", bad, bad, bad, bad, bad, bad, e, w.Logs()), marker) {
			t.Fatal("MediaRef marker exposed")
		}
	})
	t.Run("private_state", func(t *testing.T) {
		w := setup(t, h)
		send(t, w, "state", "private")
		sync(t, w.B, nil)
		for _, dir := range w.StateDirs {
			e := filepath.Walk(dir, func(_ string, info os.FileInfo, e error) error {
				if e != nil {
					return e
				}
				want := os.FileMode(0600)
				if info.IsDir() {
					want = 0700
				}
				if info.Mode().Perm() != want {
					return fmt.Errorf("state permission mismatch")
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
		}
		b, e := os.ReadFile(w.Sentinel)
		if e != nil || string(b) != "untouched" {
			t.Fatal("sibling sentinel modified")
		}
	})
}
