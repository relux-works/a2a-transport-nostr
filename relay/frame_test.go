package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"relux.works/a2a-transport-nostr/nostr"
)

func frameEvent(id string) *nostr.Event {
	return &nostr.Event{ID: strings.Repeat(id, 64), PubKey: strings.Repeat("a", 64), Sig: strings.Repeat("b", 128), Kind: 1, Tags: [][]string{}, Content: "valid"}
}
func eventFrame(id string, size int) []byte {
	e := frameEvent("c")
	raw, _ := json.Marshal([]any{"EVENT", id, e})
	e.Content += strings.Repeat("x", size-len(raw))
	raw, _ = json.Marshal([]any{"EVENT", id, e})
	return raw
}

// Actual fragmented WebSocket messages retain the normal acceptance ceiling,
// drain through the inclusive ceiling, and disconnect above it without a drop.
// Two queries on each surviving connection prove EOSE and later neighbors survive.
func TestStreamFrameBounds(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		size, dropped, events int
		disconnect            bool
	}{
		{"normal", MaxFrameBytes, 0, 3, false},
		{"normal_plus_one", MaxFrameBytes + 1, 1, 2, false},
		{"drain_ceiling", MaxDrainBytes, 1, 2, false},
		{"above_ceiling", MaxDrainBytes + 1, 0, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upgrade := websocket.Upgrader{WriteBufferSize: 512}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, err := upgrade.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer c.Close()
				for {
					var req []json.RawMessage
					if c.ReadJSON(&req) != nil {
						return
					}
					var kind, id string
					if len(req) < 2 || json.Unmarshal(req[0], &kind) != nil || kind != "REQ" || json.Unmarshal(req[1], &id) != nil {
						continue
					}
					if c.WriteJSON([]any{"EVENT", id, frameEvent("a")}) != nil {
						return
					}
					writer, err := c.NextWriter(websocket.TextMessage)
					if err != nil {
						return
					}
					if _, err = writer.Write(eventFrame(id, tc.size)); err != nil {
						return
					}
					if writer.Close() != nil {
						return
					}
					if c.WriteJSON([]any{"EVENT", id, frameEvent("b")}) != nil {
						return
					}
					if c.WriteJSON([]any{"EOSE", id}) != nil {
						return
					}
				}
			}))
			defer server.Close()
			client := &Client{URL: "ws" + strings.TrimPrefix(server.URL, "http")}
			defer client.Close()
			for i := 0; i < 2; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				events, dropped, err := client.QueryBoundedWithDrops(ctx, fmt.Sprintf("query-%d", i), Filter{}, 10)
				cancel()
				if tc.disconnect {
					if err == nil || dropped != 0 || len(events) != 1 {
						t.Fatalf("above ceiling did not disconnect honestly: events=%d dropped=%d err=%v", len(events), dropped, err)
					}
					break
				}
				if err != nil || dropped != tc.dropped || len(events) != tc.events {
					t.Fatalf("frame boundary lost events or drop count: events=%d dropped=%d err=%v", len(events), dropped, err)
				}
				if events[0].ID != strings.Repeat("a", 64) || events[len(events)-1].ID != strings.Repeat("b", 64) {
					t.Fatal("frame boundary changed neighbors")
				}
			}
		})
	}
}

// Prefix attribution does not claim authentication or invent drops for NOTICE,
// wrong subscriptions, malformed framing, or a body that did not finish draining.
func TestDiscardedSubscription(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{`["EVENT","query",{"content":"`, "query"},
		{`["EVENT","other",{"content":"`, "other"},
		{`["NOTICE","query",{`, ""},
		{`["EVENT","query",[`, ""},
		{`["EVENT",`, ""},
		{`["EVENT","",{`, ""},
	} {
		if got := discardedSubscription([]byte(tc.raw)); got != tc.want {
			t.Fatalf("prefix attribution=%q want=%q", got, tc.want)
		}
	}
	frame := make([]byte, MaxFrameBytes+1)
	for _, size := range []int{100, MaxFrameBytes + 100} {
		for _, failure := range []error{errors.New("interrupted body"), io.ErrUnexpectedEOF} {
			r := io.MultiReader(io.LimitReader(zeroReader{}, int64(size)), errorReader{failure})
			if _, discarded, err := readFrame(r, frame); !errors.Is(err, failure) || discarded {
				t.Fatal("partial message counted as completed")
			}
		}
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type measuredReader struct{ left, total, maxRemainderRead int }

func (r *measuredReader) Read(p []byte) (int, error) {
	if r.total >= MaxFrameBytes+1 && len(p) > r.maxRemainderRead {
		r.maxRemainderRead = len(p)
	}
	n := min(len(p), r.left)
	clear(p[:n])
	r.left -= n
	r.total += n
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

// A generated body avoids allocating the input. The instrument checks every
// remainder read and per-operation allocations, not whole-process RSS. Normal
// message/parser buffers are separate and fixed; this does not bound test relay
// storage or the allocations used to parse accepted normal messages.
func TestDrainMemoryBound(t *testing.T) {
	frame := make([]byte, MaxFrameBytes+1)
	for _, size := range []int{MaxFrameBytes + 1, MaxDrainBytes, MaxDrainBytes + 1} {
		r := &measuredReader{left: size}
		raw, discarded, err := readFrame(r, frame)
		if size <= MaxDrainBytes {
			if err != nil || !discarded || len(raw) != MaxFrameBytes+1 {
				t.Fatal("bounded drain refused permitted size")
			}
		} else if !errors.Is(err, errDrainLimit) || discarded {
			t.Fatal("drain ceiling was bypassed")
		}
		if r.total > MaxDrainBytes+1 || r.maxRemainderRead > drainScratchBytes {
			t.Fatal("drain buffered beyond fixed scratch")
		}
	}
	bench := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			r := &measuredReader{left: MaxDrainBytes}
			if _, discarded, err := readFrame(r, frame); err != nil || !discarded {
				b.Fatal("drain failed")
			}
		}
	})
	if bench.AllocedBytesPerOp() > 8<<10 {
		t.Fatalf("drain allocations exceed fixed scratch budget: %d", bench.AllocedBytesPerOp())
	}
	t.Logf("drain allocation bytes/op=%d; normal prefix=%d; scratch=%d", bench.AllocedBytesPerOp(), len(frame), drainScratchBytes)
}

// A query counts only fully drained EVENT messages addressed to its own
// subscription. Other subscriptions and oversized NOTICE messages do not count.
func TestDrainAttribution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{WriteBufferSize: 512}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		var req []json.RawMessage
		if c.ReadJSON(&req) != nil {
			return
		}
		for _, raw := range [][]byte{eventFrame("other", MaxFrameBytes+1), []byte(`["NOTICE","` + strings.Repeat("x", MaxFrameBytes) + `"]`), eventFrame("query", MaxFrameBytes+1)} {
			if c.WriteMessage(websocket.TextMessage, raw) != nil {
				return
			}
		}
		if c.WriteJSON([]any{"EVENT", "query", frameEvent("a")}) != nil {
			return
		}
		if c.WriteJSON([]any{"EOSE", "query"}) != nil {
			return
		}
		// Keep the connection alive until the client closes it.
		for {
			if _, _, err = c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	client := &Client{URL: "ws" + strings.TrimPrefix(server.URL, "http")}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	events, dropped, err := client.QueryBoundedWithDrops(ctx, "query", Filter{}, 10)
	if err != nil || len(events) != 1 || dropped != 1 {
		t.Fatalf("drain attribution changed: events=%d dropped=%d err=%v", len(events), dropped, err)
	}
}

// Cancellation closes a partially drained fragmented message, makes no completed
// drop claim, and releases the socket; a stalled peer cannot carry that body into
// a later query. The server confirms actual connection closure without sleeps.
func TestDrainCancellation(t *testing.T) {
	sent, closed := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{WriteBufferSize: 512}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		defer close(closed)
		var req []json.RawMessage
		if c.ReadJSON(&req) != nil {
			return
		}
		writer, err := c.NextWriter(websocket.TextMessage)
		if err != nil {
			return
		}
		// Deliberately omit the final fragment.
		if _, err = writer.Write(eventFrame("query", MaxFrameBytes+8192)); err != nil {
			return
		}
		close(sent)
		for {
			if _, _, err = c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	client := &Client{URL: "ws" + strings.TrimPrefix(server.URL, "http")}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		events, dropped int
		err             error
	}
	done := make(chan result, 1)
	go func() {
		events, dropped, err := client.QueryBoundedWithDrops(ctx, "query", Filter{}, 10)
		done <- result{len(events), dropped, err}
	}()
	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatal("partial frame was not sent")
	}
	cancel()
	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) || got.events != 0 || got.dropped != 0 {
			t.Fatal("partial drain cancellation changed result")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("query did not cancel")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled drain left socket open")
	}
}
