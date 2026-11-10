// Package testrelay is an in-process, localhost-only Nostr relay for
// tests. It speaks the subset the transport needs (EVENT/REQ/CLOSE ->
// EVENT/EOSE/OK/NOTICE), verifies event ids and signatures exactly
// like a real relay, keeps events in memory, and binds 127.0.0.1
// only. It exists so conformance tests never touch a real relay.
package testrelay

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/relux-works/a2a-transport-nostr/nostr"
)

// Filter is the NIP-01 subscription filter subset we support.
type Filter struct {
	IDs     []string `json:"ids,omitempty"`
	Kinds   []int    `json:"kinds,omitempty"`
	Authors []string `json:"authors,omitempty"`
	PTags   []string `json:"#p,omitempty"`
	Since   *int64   `json:"since,omitempty"`
	Until   *int64   `json:"until,omitempty"`
	Limit   int      `json:"limit,omitempty"`
}

// Match reports whether an event passes the filter.
func (f *Filter) Match(e *nostr.Event) bool {
	if len(f.IDs) > 0 && !containsStr(f.IDs, e.ID) {
		return false
	}
	if len(f.Kinds) > 0 && !containsInt(f.Kinds, e.Kind) {
		return false
	}
	if len(f.Authors) > 0 && !containsStr(f.Authors, e.PubKey) {
		return false
	}
	if len(f.PTags) > 0 {
		p, ok := e.TagFirst("p")
		if !ok || !containsStr(f.PTags, p) {
			return false
		}
	}
	if f.Since != nil && e.CreatedAt < *f.Since {
		return false
	}
	if f.Until != nil && e.CreatedAt > *f.Until {
		return false
	}
	return true
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func containsStr(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// Options controls negative-test relay behaviours.
type Options struct {
	TrueDuplicate bool // Return OK true on duplicate; false preserves legacy fixture behavior.
	RequireAuth   bool // NIP-42: challenge every connection first
	// OKMode: "" normal, "reject" (OK false blocked:), "silent" (never answer OK).
	OKMode string
	// LooseAuthors makes REQ matching ignore the authors filter,
	// like a malicious or buggy relay that answers an author query
	// with somebody else's events.
	LooseAuthors bool
}

// Relay is the test relay server.
type Relay struct {
	opts Options
	URL  string // ws://127.0.0.1:<port>

	ln     net.Listener
	server *http.Server

	mu       sync.Mutex
	events   []*nostr.Event
	seen     map[string]bool
	subs     map[*conn]map[string][]*Filter
	modes    map[string]string
	calls    int
	attempts map[string]int
}

type conn struct {
	ws        *websocket.Conn
	mu        sync.Mutex
	challenge string
	authed    bool
}

func (c *conn) sendJSON(v any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ws.WriteJSON(v)
}

// Start binds the relay on a random 127.0.0.1 port and serves.
func Start() (*Relay, error) { return StartWithOptions(Options{}) }

// StartWithOptions is Start with negative-test behaviours.
func StartWithOptions(opts Options) (*Relay, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r := &Relay{
		opts:  opts,
		URL:   fmt.Sprintf("ws://%s", ln.Addr().String()),
		ln:    ln,
		seen:  map[string]bool{},
		modes: map[string]string{}, attempts: map[string]int{},
		subs: map[*conn]map[string][]*Filter{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", r.handle)
	r.server = &http.Server{Handler: mux}
	go func() { _ = r.server.Serve(ln) }()
	return r, nil
}

// Close shuts the relay down.
func (r *Relay) Close() {
	r.mu.Lock()
	for c := range r.subs {
		_ = c.ws.Close()
	}
	r.mu.Unlock()
	if r.server != nil {
		_ = r.server.Close()
	}
	_ = r.ln.Close()
}

// SetRecipientMode changes only the local test relay's publish fault for a key.
// Modes: silent, after-submit (store without response), reject, false-duplicate.
func (r *Relay) SetRecipientMode(key, mode string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.modes[key] = mode
}
func (r *Relay) Calls() int             { r.mu.Lock(); defer r.mu.Unlock(); return r.calls }
func (r *Relay) Attempts(id string) int { r.mu.Lock(); defer r.mu.Unlock(); return r.attempts[id] }

// Events returns a copy of stored events (oldest first) for asserts.
func (r *Relay) Events() []*nostr.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*nostr.Event(nil), r.events...)
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(*http.Request) bool { return true },
}

func (r *Relay) handle(w http.ResponseWriter, req *http.Request) {
	ws, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		return
	}
	c := &conn{ws: ws}
	if r.opts.RequireAuth {
		ch := make([]byte, 16)
		_, _ = rand.Read(ch)
		c.challenge = hex.EncodeToString(ch)
		_ = c.sendJSON([]any{"AUTH", c.challenge})
	} else {
		c.authed = true
	}
	r.mu.Lock()
	r.subs[c] = map[string][]*Filter{}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.subs, c)
		r.mu.Unlock()
		_ = ws.Close()
	}()
	for {
		_, raw, err := ws.ReadMessage()
		if err != nil {
			return
		}
		r.dispatch(c, raw)
	}
}

func (r *Relay) dispatch(c *conn, raw []byte) {
	var msg []json.RawMessage
	if err := json.Unmarshal(raw, &msg); err != nil || len(msg) == 0 {
		_ = c.sendJSON([]any{"NOTICE", "invalid message"})
		return
	}
	var typ string
	_ = json.Unmarshal(msg[0], &typ)
	if typ != "CLOSE" {
		r.mu.Lock()
		r.calls++
		r.mu.Unlock()
	}
	switch typ {
	case "AUTH":
		if len(msg) != 2 {
			return
		}
		ev, err := nostr.ParseEvent(msg[1])
		if err != nil || ev.Kind != nostr.KindAuth || nostr.VerifySignature(ev) != nil {
			return
		}
		if ch, ok := ev.TagFirst("challenge"); ok && ch == c.challenge && c.challenge != "" {
			c.authed = true
			_ = c.sendJSON([]any{"OK", ev.ID, true, ""})
		}
		return
	case "EVENT":
		if len(msg) != 2 {
			return
		}
		if r.opts.RequireAuth && !c.authed {
			var probe struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(msg[1], &probe)
			_ = c.sendJSON([]any{"OK", probe.ID, false, "auth-required: we only accept events from registered users"})
			return
		}
		if r.opts.OKMode == "silent" {
			return
		}
		if len(msg) != 2 {
			_ = c.sendJSON([]any{"NOTICE", "EVENT wants one event"})
			return
		}
		ev, err := nostr.ParseEvent(msg[1])
		if err != nil {
			_ = c.sendJSON([]any{"OK", "", false, "invalid: " + err.Error()})
			return
		}
		if err := nostr.VerifySignature(ev); err != nil {
			_ = c.sendJSON([]any{"OK", ev.ID, false, "invalid: " + err.Error()})
			return
		}
		recipient, _ := ev.TagFirst("p")
		r.mu.Lock()
		mode := r.modes[recipient]
		r.attempts[ev.ID]++
		r.mu.Unlock()
		if mode == "silent" {
			return
		}
		if mode == "reject" {
			_ = c.sendJSON([]any{"OK", ev.ID, false, "blocked: test refusal"})
			return
		}
		if r.opts.OKMode == "reject" {
			_ = c.sendJSON([]any{"OK", ev.ID, false, "blocked: test relay rejects everything"})
			return
		}
		r.mu.Lock()
		if r.seen[ev.ID] {
			r.mu.Unlock()
			if mode == "after-submit" {
				return
			}
			_ = c.sendJSON([]any{"OK", ev.ID, r.opts.TrueDuplicate && mode != "false-duplicate", "duplicate: already have this event"})
			return
		}
		r.seen[ev.ID] = true
		r.events = append(r.events, ev)
		targets := r.matchingSubsLocked(ev)
		r.mu.Unlock()
		if mode != "after-submit" {
			_ = c.sendJSON([]any{"OK", ev.ID, true, ""})
		}
		for _, t := range targets {
			_ = t.c.sendJSON([]any{"EVENT", t.subID, ev})
		}
	case "REQ":
		if len(msg) < 3 {
			_ = c.sendJSON([]any{"NOTICE", "REQ wants id and filters"})
			return
		}
		var subID string
		_ = json.Unmarshal(msg[1], &subID)
		if r.opts.RequireAuth && !c.authed {
			_ = c.sendJSON([]any{"CLOSED", subID, "auth-required: we only serve registered users"})
			return
		}
		var filters []*Filter
		for _, fr := range msg[2:] {
			var f Filter
			if err := json.Unmarshal(fr, &f); err == nil {
				if r.opts.LooseAuthors {
					f.Authors = nil
				}
				filters = append(filters, &f)
			}
		}
		r.mu.Lock()
		r.subs[c][subID] = filters
		stored := append([]*nostr.Event(nil), r.events...)
		r.mu.Unlock()
		for _, ev := range stored {
			if matchAny(filters, ev) {
				_ = c.sendJSON([]any{"EVENT", subID, ev})
			}
		}
		_ = c.sendJSON([]any{"EOSE", subID})
	case "CLOSE":
		if len(msg) == 2 {
			var subID string
			_ = json.Unmarshal(msg[1], &subID)
			r.mu.Lock()
			delete(r.subs[c], subID)
			r.mu.Unlock()
		}
	default:
		_ = c.sendJSON([]any{"NOTICE", "unknown message type"})
	}
}

type subTarget struct {
	c     *conn
	subID string
}

func (r *Relay) matchingSubsLocked(ev *nostr.Event) []subTarget {
	var out []subTarget
	for c, subs := range r.subs {
		for subID, filters := range subs {
			if matchAny(filters, ev) {
				out = append(out, subTarget{c, subID})
			}
		}
	}
	return out
}

func matchAny(filters []*Filter, ev *nostr.Event) bool {
	for _, f := range filters {
		if f.Match(ev) {
			return true
		}
	}
	return false
}

// DiscardEvents simulates a local relay retention boundary; counters are retained.
func (r *Relay) DiscardEvents() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = nil
	r.seen = map[string]bool{}
}
