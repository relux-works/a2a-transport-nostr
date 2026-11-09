// Package relay is a minimal Nostr relay client: publish with
// OK classification (accepted / duplicate / rejected), subscription
// streams, and NIP-42 AUTH. One read pump per connection dispatches
// OK replies and events.
package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"relux.works/a2a-transport-nostr/nostr"
)

// Filter is a NIP-01 subscription filter (subset).
type Filter struct {
	IDs     []string `json:"ids,omitempty"`
	Kinds   []int    `json:"kinds,omitempty"`
	Authors []string `json:"authors,omitempty"`
	PTags   []string `json:"#p,omitempty"`
	Since   *int64   `json:"since,omitempty"`
	Until   *int64   `json:"until,omitempty"`
	Limit   int      `json:"limit,omitempty"`
}

// OKResult classifies a relay OK reply.
type OKResult struct {
	Original  bool // A syntactically valid OK frame for this original event, not a local connection error.
	Accepted  bool
	Duplicate bool // OK false with a "duplicate:" reason still means stored
	Reason    string
}

// Stored reports whether the relay holds the event.
func (r OKResult) Stored() bool { return r.Accepted || r.Duplicate }

// EventHandler receives subscription events; eose=true marks the
// end of the stored backlog for that subscription (ev is nil).
type EventHandler func(subID string, ev *nostr.Event, eose bool)

// Client is one websocket connection to one relay.
type Client struct {
	URL string
	// AuthKey, when set, answers NIP-42 AUTH challenges.
	AuthKey *nostr.PrivKey

	mu      sync.Mutex
	conn    *websocket.Conn
	waiters map[string]chan OKResult
	subs    map[string]Filter
	handler EventHandler
	hctx    context.Context
	pumpErr chan error
	now     func() time.Time
}

// Dial connects and starts the pump (idempotent).
func (c *Client) Dial(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return nil
	}
	d := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := d.DialContext(ctx, c.URL, nil)
	if err != nil {
		return err
	}
	conn.SetReadLimit(256 << 10)
	c.conn = conn
	c.waiters = map[string]chan OKResult{}
	c.subs = map[string]Filter{}
	c.pumpErr = make(chan error, 1)
	if c.now == nil {
		c.now = time.Now
	}
	go c.pump(conn)
	return nil
}

// Close ends the connection; pending publishes fail.
func (c *Client) Close() {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (c *Client) writeJSON(v any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return fmt.Errorf("relay: not connected")
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return c.conn.WriteJSON(v)
}

func (c *Client) pump(conn *websocket.Conn) {
	var pumpErr error
	defer func() {
		c.mu.Lock()
		if c.conn != conn {
			c.mu.Unlock()
			return
		}
		c.conn = nil
		waiters := c.waiters
		c.waiters = map[string]chan OKResult{}
		errCh := c.pumpErr
		c.mu.Unlock()
		for _, ch := range waiters {
			if pumpErr == nil {
				pumpErr = fmt.Errorf("relay: connection closed")
			}
			ch <- OKResult{Reason: pumpErr.Error()}
		}
		if errCh != nil {
			errCh <- pumpErr
		}
	}()
	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			pumpErr = err
			return
		}
		var msg []json.RawMessage
		if json.Unmarshal(raw, &msg) != nil || len(msg) < 1 {
			continue
		}
		var typ string
		_ = json.Unmarshal(msg[0], &typ)
		switch typ {
		case "OK":
			if len(msg) < 4 {
				continue
			}
			var id, reason string
			var accepted bool
			if json.Unmarshal(msg[1], &id) != nil || json.Unmarshal(msg[2], &accepted) != nil || json.Unmarshal(msg[3], &reason) != nil {
				continue
			}
			c.mu.Lock()
			ch := c.waiters[id]
			delete(c.waiters, id)
			c.mu.Unlock()
			if ch != nil {
				ch <- OKResult{Original: true, Accepted: accepted,
					Duplicate: !accepted && strings.HasPrefix(reason, "duplicate:"),
					Reason:    reason}
			}
		case "EVENT":
			if len(msg) != 3 {
				continue
			}
			var subID string
			_ = json.Unmarshal(msg[1], &subID)
			ev, err := nostr.ParseEvent(msg[2])
			if err != nil {
				continue
			}
			c.mu.Lock()
			h := c.handler
			c.mu.Unlock()
			if h != nil {
				h(subID, ev, false)
			}
		case "EOSE":
			if len(msg) < 2 {
				continue
			}
			var subID string
			_ = json.Unmarshal(msg[1], &subID)
			c.mu.Lock()
			h := c.handler
			c.mu.Unlock()
			if h != nil {
				h(subID, nil, true)
			}
		case "AUTH":
			if len(msg) < 2 || c.AuthKey == nil {
				continue
			}
			var challenge string
			_ = json.Unmarshal(msg[1], &challenge)
			ev, err := nostr.BuildAuthEvent(c.AuthKey, c.URL, challenge, c.now().Unix())
			if err == nil {
				_ = c.writeJSON([]any{"AUTH", ev})
				// Re-issue subscriptions: relays typically closed
				// pre-auth REQs with auth-required.
				c.mu.Lock()
				subs := make(map[string]Filter, len(c.subs))
				for id, f := range c.subs {
					subs[id] = f
				}
				c.mu.Unlock()
				for id, f := range subs {
					_ = c.writeJSON([]any{"REQ", id, f})
				}
			}
		case "CLOSED":
			// Pre-auth closures are healed by the AUTH re-REQ above;
			// other closures drop the subscription record.
			if len(msg) >= 3 {
				var subID, reason string
				_ = json.Unmarshal(msg[1], &subID)
				_ = json.Unmarshal(msg[2], &reason)
				if !strings.HasPrefix(reason, "auth-required") {
					c.mu.Lock()
					delete(c.subs, subID)
					c.mu.Unlock()
				}
				// auth-required: the AUTH handler re-REQs; Query
				// waiters stay pending for the real EOSE (or ctx).
			}
		}
	}
}

// Publish writes one event and awaits its OK (default 10s when ctx
// has no deadline). An auth-required rejection is retried after the
// NIP-42 handshake settles (the challenge may not have been
// processed when the first EVENT was written). A timeout or
// disconnect returns an error; other rejections return the
// classified OKResult with Stored()=false.
func (c *Client) Publish(ctx context.Context, ev *nostr.Event) (OKResult, error) {
	res, err := c.publishOnce(ctx, ev)
	for attempt := 0; err == nil && !res.Stored() &&
		strings.HasPrefix(res.Reason, "auth-required:") && c.AuthKey != nil && attempt < 20; attempt++ {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		res, err = c.publishOnce(ctx, ev)
	}
	return res, err
}

func (c *Client) publishOnce(ctx context.Context, ev *nostr.Event) (OKResult, error) {
	if err := c.Dial(ctx); err != nil {
		return OKResult{}, err
	}
	ch := make(chan OKResult, 1)
	c.mu.Lock()
	if c.waiters == nil {
		c.waiters = map[string]chan OKResult{}
	}
	c.waiters[ev.ID] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.waiters, ev.ID)
		c.mu.Unlock()
	}()
	if err := c.writeJSON([]any{"EVENT", ev}); err != nil {
		return OKResult{}, err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	select {
	case res := <-ch:
		return res, nil
	case <-ctx.Done():
		return OKResult{}, ctx.Err()
	}
}

// Subscribe registers a handler and sends one REQ. Events and EOSE
// arrive through the pump. Use Unsubscribe to CLOSE.
func (c *Client) Subscribe(ctx context.Context, subID string, f Filter, h EventHandler) error {
	if err := c.Dial(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	c.handler = h
	c.hctx = ctx
	if c.subs == nil {
		c.subs = map[string]Filter{}
	}
	c.subs[subID] = f
	c.mu.Unlock()
	return c.writeJSON([]any{"REQ", subID, f})
}

// Unsubscribe sends CLOSE for one subscription.
func (c *Client) Unsubscribe(subID string) error {
	c.mu.Lock()
	delete(c.subs, subID)
	c.mu.Unlock()
	return c.writeJSON([]any{"CLOSE", subID})
}

// Query runs one REQ and returns events until EOSE (bounded by ctx).
// It temporarily takes over the event handler, so callers use one
// Client per query stream; Subscribe and Query must not share a
// client concurrently.
// ErrQueryLimit marks a bounded incomplete backlog, never a successful EOSE.
var ErrQueryLimit = errors.New("relay: query limit")

func (c *Client) Query(ctx context.Context, subID string, f Filter) ([]*nostr.Event, error) {
	return c.QueryBounded(ctx, subID, f, 4096)
}

// QueryBounded returns a detached bounded snapshot and closes its callback on
// timeout/failure. A delayed callback cannot race with or mutate returned data.
func (c *Client) QueryBounded(ctx context.Context, subID string, f Filter, limit int) ([]*nostr.Event, error) {
	if limit < 1 || limit > 4096 {
		return nil, ErrQueryLimit
	}
	var mu sync.Mutex
	var out []*nostr.Event
	var stopped, limited bool
	done := make(chan struct{})
	var once sync.Once
	err := c.Subscribe(ctx, subID, f, func(id string, ev *nostr.Event, eose bool) {
		if id != subID {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if stopped {
			return
		}
		if eose {
			stopped = true
			once.Do(func() { close(done) })
			return
		}
		if ev != nil {
			if len(out) == limit {
				limited = true
				stopped = true
				once.Do(func() { close(done) })
				return
			}
			out = append(out, ev)
		}
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Unsubscribe(subID) }()
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
	}
	select {
	case <-done:
	case <-ctx.Done():
		err = ctx.Err()
	case <-c.PumpErr():
		err = errors.New("relay: query disconnected")
	}
	mu.Lock()
	defer mu.Unlock()
	stopped = true
	if limited {
		err = ErrQueryLimit
	}
	return append([]*nostr.Event(nil), out...), err
}

// PumpErr exposes the pump termination error (Subscribe loops).
func (c *Client) PumpErr() <-chan error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pumpErr
}
