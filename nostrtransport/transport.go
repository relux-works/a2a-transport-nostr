// Package nostrtransport implements the a2a transport interface
// over Nostr private messages (NIP-17/44/59), Blossom media and
// NIP-65/10050 relay routing. The verified sender is always the
// inner seal key; sends are exactly-once by persisted signed bytes.
package nostrtransport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/relux-works/a2a-transport-nostr/blossom"
	"github.com/relux-works/a2a-transport-nostr/nostr"
	"github.com/relux-works/a2a-transport-nostr/relay"
	"github.com/relux-works/a2a-transport-nostr/transport"
)

// Errors returned by the transport.
var (
	ErrIdempotencyConflict = errors.New("nostrtransport: idempotency key reused with different content")
	ErrTooLarge            = errors.New("nostrtransport: message too large")
	ErrBadConversation     = errors.New("nostrtransport: bad conversation id")
)

// Config wires one transport instance. Key is required; Relays are
// the identity's own read/write set and the routing fallback.
type Config struct {
	Key             *nostr.PrivKey
	StateDir        string
	ReadRelays      []string
	WriteRelays     []string
	DMRelays        []string // own kind 10050 set; default falls back to ReadRelays
	DiscoveryRelays []string // for 10002/10050 lookups; default ReadRelays
	BlossomServers  []string
	PublishQuorum   int           // per wrap; default 1
	SkewWindow      time.Duration // default 48h+300s (NIP-59 jitter)
	MaxContent      int           // bytes; default 60000
	Now             func() time.Time
}

type convJSON struct {
	P []string `json:"p"`
	S string   `json:"s,omitempty"`
}

// sendCall is one in-flight coalesced send: the owner fills the
// result, waiters on done receive it (RN1-01 N4).
type sendCall struct {
	done chan struct{}
	hash string // owner's content hash; waiters must match
	id   string
	ack  transport.AckStatus
	err  error
}

// Transport is the Nostr implementation of transport.Transport.
type Transport struct {
	cfg     Config
	store   *store
	blossom *blossom.Client

	mu      sync.Mutex
	clients map[string]*relay.Client
	routes  map[string]routeEntry
	cursor  cursorState

	sendMu   sync.Mutex
	inflight map[string]*sendCall
}

type routeEntry struct {
	urls []string
	at   time.Time
}

// New validates config and loads persisted sync state.
func New(cfg Config) (*Transport, error) {
	if cfg.Key == nil {
		return nil, fmt.Errorf("nostrtransport: identity key required")
	}
	if len(cfg.ReadRelays) == 0 && len(cfg.WriteRelays) == 0 {
		return nil, fmt.Errorf("nostrtransport: at least one relay required")
	}
	if len(cfg.ReadRelays) == 0 {
		cfg.ReadRelays = cfg.WriteRelays
	}
	if len(cfg.WriteRelays) == 0 {
		cfg.WriteRelays = cfg.ReadRelays
	}
	if len(cfg.DiscoveryRelays) == 0 {
		cfg.DiscoveryRelays = cfg.ReadRelays
	}
	if cfg.PublishQuorum <= 0 {
		cfg.PublishQuorum = 1
	}
	if cfg.SkewWindow <= 0 {
		cfg.SkewWindow = 48*time.Hour + 5*time.Minute
	}
	if cfg.MaxContent <= 0 {
		cfg.MaxContent = 60000
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	st, err := openStore(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	cur, err := st.loadCursor()
	if err != nil {
		return nil, err
	}
	return &Transport{
		cfg: cfg, store: st, cursor: cur,
		clients:  map[string]*relay.Client{},
		routes:   map[string]routeEntry{},
		inflight: map[string]*sendCall{},
		blossom:  &blossom.Client{Signer: cfg.Key, Now: cfg.Now},
	}, nil
}

// Identity returns the own public key (hex).
func (t *Transport) Identity() string { return t.cfg.Key.PubKeyHex() }

// Capabilities reports the fixed Nostr capability set.
func (t *Transport) Capabilities() transport.Capabilities {
	return transport.Capabilities{E2EE: true, Redaction: "best_effort",
		Receipts: false, Membership: "sender_side"}
}

// Close ends all relay connections.
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range t.clients {
		c.Close()
	}
	t.clients = map[string]*relay.Client{}
	return nil
}

func (t *Transport) nowUnix() int64 { return t.cfg.Now().Unix() }

// NewConversation builds an opaque private-conversation id from the
// other participants (self is added) and an optional subject.
func (t *Transport) NewConversation(others []string, subject string) transport.ConversationID {
	all := nostr.SortedUnique(append(append([]string{}, others...), t.Identity()))
	raw, _ := json.Marshal(convJSON{P: all, S: subject})
	return transport.ConversationID(raw)
}

func parseConversation(id transport.ConversationID) (convJSON, error) {
	var c convJSON
	if len(id) == 0 || json.Unmarshal(id, &c) != nil || len(c.P) == 0 {
		return c, ErrBadConversation
	}
	c.P = nostr.SortedUnique(c.P)
	return c, nil
}

func (t *Transport) clientFor(url string) *relay.Client {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.clients[url]
	if !ok {
		c = &relay.Client{URL: url, AuthKey: t.cfg.Key}
		t.clients[url] = c
	}
	return c
}

// resolve finds publish relays for one recipient: kind 10050 DM
// relays, else kind 10002 write relays, else own write relays.
// Results are cached briefly; discovery failures fall back.
func (t *Transport) resolve(ctx context.Context, pubkey string) []string {
	if pubkey == t.Identity() {
		if len(t.cfg.DMRelays) > 0 {
			return t.cfg.DMRelays
		}
		return t.cfg.WriteRelays
	}
	t.mu.Lock()
	if e, ok := t.routes[pubkey]; ok && t.cfg.Now().Sub(e.at) < 5*time.Minute {
		t.mu.Unlock()
		return e.urls
	}
	t.mu.Unlock()
	var dm, write []string
	var dmAt, writeAt int64
	for _, url := range t.cfg.DiscoveryRelays {
		c := t.clientFor(url)
		qctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		evs, err := c.Query(qctx, "route", relay.Filter{
			Kinds: []int{nostr.KindRelayList, nostr.KindDMRelays}, Authors: []string{pubkey}})
		cancel()
		if err != nil {
			continue
		}
		for _, ev := range evs {
			// Pin the author to the queried pubkey: a relay must
			// not redirect routing with somebody else's signed
			// relay list (RN1-01 N2).
			if ev.PubKey != pubkey || nostr.VerifySignature(ev) != nil {
				continue
			}
			switch ev.Kind {
			case nostr.KindDMRelays:
				if ev.CreatedAt >= dmAt {
					dmAt, dm = ev.CreatedAt, nostr.ParseDMRelays(ev)
				}
			case nostr.KindRelayList:
				if ev.CreatedAt >= writeAt {
					_, w := nostr.ParseRelayList(ev)
					writeAt, write = ev.CreatedAt, w
				}
			}
		}
		if len(dm) > 0 {
			break
		}
	}
	urls := dm
	if len(urls) == 0 {
		urls = write
	}
	if len(urls) == 0 {
		urls = t.cfg.WriteRelays
	}
	t.mu.Lock()
	t.routes[pubkey] = routeEntry{urls: urls, at: t.cfg.Now()}
	t.mu.Unlock()
	return urls
}

// PublishRelayLists publishes own kind 10002 + kind 10050 events
// to the configured relays (best effort per relay).
func (t *Transport) PublishRelayLists(ctx context.Context) error {
	list, err := nostr.BuildRelayListEvent(t.cfg.Key, t.cfg.ReadRelays, t.cfg.WriteRelays, t.nowUnix())
	if err != nil {
		return err
	}
	dm := t.cfg.DMRelays
	if len(dm) == 0 {
		dm = t.cfg.ReadRelays
	}
	dmEv, err := nostr.BuildDMRelaysEvent(t.cfg.Key, dm, t.nowUnix())
	if err != nil {
		return err
	}
	var firstErr error
	anyOK := false
	for _, url := range union(t.cfg.ReadRelays, t.cfg.WriteRelays) {
		c := t.clientFor(url)
		for _, ev := range []*nostr.Event{list, dmEv} {
			res, err := c.Publish(ctx, ev)
			if err == nil && res.Stored() {
				anyOK = true
			} else if firstErr == nil && err != nil {
				firstErr = err
			}
		}
	}
	if !anyOK {
		return firstErr
	}
	return nil
}

func union(a, b []string) []string {
	return nostr.SortedUnique(append(append([]string{}, a...), b...))
}

func sortMessages(ms []transport.Message) {
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].CreatedAt != ms[j].CreatedAt {
			return ms[i].CreatedAt < ms[j].CreatedAt
		}
		return ms[i].ID < ms[j].ID
	})
}
