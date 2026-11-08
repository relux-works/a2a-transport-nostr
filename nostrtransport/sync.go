package nostrtransport

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"relux.works/a2a-transport-nostr/nostr"
	"relux.works/a2a-transport-nostr/relay"
	"relux.works/a2a-transport-nostr/transport"
)

func encodeCursor(c cursorState) transport.Cursor {
	raw, _ := json.Marshal(cursorState{Since: c.Since, WrapIDs: c.WrapIDs, RumorIDs: c.RumorIDs})
	return transport.Cursor(raw)
}

// stateFor resolves the effective cursor state: an explicit cursor
// wins over empty; empty resumes from the persisted state (which
// also owns tombstones).
func (t *Transport) stateFor(cursor transport.Cursor) (cursorState, error) {
	t.mu.Lock()
	cur := t.cursor
	t.mu.Unlock()
	if len(cursor) == 0 {
		return cur, nil
	}
	var c cursorState
	if err := json.Unmarshal(cursor, &c); err != nil {
		return cur, fmt.Errorf("nostrtransport: bad cursor: %w", err)
	}
	c.Tombstones = cur.Tombstones
	return c, nil
}

func (t *Transport) saveState(c cursorState) {
	t.mu.Lock()
	t.cursor = c
	t.mu.Unlock()
	_ = t.store.saveCursor(c)
}

// processWrap unwraps and converts one gift wrap under a working
// cursor state. Returns nil for seen/refused/tombstoned traffic.
func (t *Transport) processWrap(state *cursorState, wrap *nostr.Event) *transport.Message {
	now := t.nowUnix()
	if state.seenWrap(wrap.ID) {
		return nil
	}
	state.WrapIDs = appendBounded(state.WrapIDs, wrap.ID)
	if wrap.CreatedAt > state.Since {
		state.Since = wrap.CreatedAt
	}
	if wrap.CreatedAt > now+900 {
		return nil // far-future: refused, never delivered
	}
	unwrapped, err := nostr.UnwrapDM(wrap, t.cfg.Key)
	if err != nil {
		return nil
	}
	rumor := unwrapped.Rumor
	if rumor.CreatedAt > now+900 {
		return nil
	}
	if state.seenRumor(rumor.ID) || state.tombstoned(rumor.ID) {
		return nil
	}
	state.RumorIDs = appendBounded(state.RumorIDs, rumor.ID)

	participants := map[string]bool{}
	for _, tag := range rumor.Tags {
		if len(tag) >= 2 && tag[0] == "p" {
			participants[tag[1]] = true
		}
	}
	participants[unwrapped.SenderHex] = true
	participants[t.Identity()] = true
	plist := make([]string, 0, len(participants))
	for p := range participants {
		plist = append(plist, p)
	}
	subject, _ := rumor.TagFirst("subject")
	convRaw, _ := json.Marshal(convJSON{P: nostr.SortedUnique(plist), S: subject})
	kind, _ := rumor.TagFirst("a2a-kind")
	var replyTo, root string
	for _, tag := range rumor.Tags {
		if len(tag) >= 4 && tag[0] == "e" {
			if tag[3] == "reply" {
				replyTo = tag[1]
			}
			if tag[3] == "root" {
				root = tag[1]
			}
		}
	}
	msg := &transport.Message{
		ID: rumor.ID, Conversation: transport.ConversationID(convRaw),
		Sender: unwrapped.SenderHex, Content: rumor.Content,
		CreatedAt: rumor.CreatedAt, ReplyTo: replyTo, Root: root,
		Kind: kind, Participants: nostr.SortedUnique(plist),
	}
	if rumor.Kind == nostr.KindFileMessage {
		if url, mime, k, n, x, ox, ok := nostr.ParseFileTags(rumor); ok {
			msg.File = &transport.FileRef{URL: url, Mime: mime,
				CipherSHA256: x, PlainSHA256: ox, DecryptionKey: k, Nonce: n}
		}
	}
	return msg
}

// Sync implements transport.Transport: one backlog pass per read
// relay, EOSE-terminated, deduplicated across relays and restarts.
func (t *Transport) Sync(ctx context.Context, cursor transport.Cursor) ([]transport.Message, transport.Cursor, error) {
	state, err := t.stateFor(cursor)
	if err != nil {
		return nil, cursor, err
	}
	since := state.Since - int64(t.cfg.SkewWindow/time.Second)
	if since < 0 {
		since = 0
	}
	filter := relay.Filter{Kinds: []int{nostr.KindGiftWrap},
		PTags: []string{t.Identity()}, Since: &since}
	var msgs []transport.Message
	var firstErr error
	anyOK := false
	for _, url := range union(t.cfg.ReadRelays, t.cfg.DMRelays) {
		c := t.clientFor(url)
		qctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		evs, err := c.Query(qctx, "sync", filter)
		cancel()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		anyOK = true
		for _, ev := range evs {
			if m := t.processWrap(&state, ev); m != nil {
				msgs = append(msgs, *m)
			}
		}
	}
	sortMessages(msgs)
	t.saveState(state)
	if !anyOK && firstErr != nil {
		return msgs, encodeCursor(state), firstErr
	}
	return msgs, encodeCursor(state), nil
}

// Subscribe delivers the backlog, then live wraps, until ctx ends.
func (t *Transport) Subscribe(ctx context.Context, cursor transport.Cursor,
	handler func(transport.Message)) (transport.Cursor, error) {
	msgs, next, err := t.Sync(ctx, cursor)
	if err != nil && len(msgs) == 0 {
		return next, err
	}
	for _, m := range msgs {
		handler(m)
	}
	state, err := t.stateFor(next)
	if err != nil {
		return next, err
	}
	since := state.Since - int64(t.cfg.SkewWindow/time.Second)
	if since < 0 {
		since = 0
	}
	filter := relay.Filter{Kinds: []int{nostr.KindGiftWrap},
		PTags: []string{t.Identity()}, Since: &since}
	var mu sync.Mutex
	live := func(subID string, ev *nostr.Event, eose bool) {
		if eose || ev == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if m := t.processWrap(&state, ev); m != nil {
			t.saveState(state)
			handler(*m)
		} else {
			t.saveState(state)
		}
	}
	var firstErr error
	started := 0
	for _, url := range union(t.cfg.ReadRelays, t.cfg.DMRelays) {
		c := t.clientFor(url)
		if err := c.Subscribe(ctx, "live", filter, live); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		started++
	}
	if started == 0 {
		return encodeCursor(state), firstErr
	}
	<-ctx.Done()
	return encodeCursor(state), ctx.Err()
}

// Membership returns the conversation participant set (sender-side
// membership: the p set is the membership).
func (t *Transport) Membership(ctx context.Context, conv transport.ConversationID) ([]string, error) {
	cj, err := parseConversation(conv)
	if err != nil {
		return nil, err
	}
	return cj.P, nil
}

// PutMedia stores a blob on the first answering server.
func (t *Transport) PutMedia(ctx context.Context, data []byte) (string, error) {
	if len(t.cfg.BlossomServers) == 0 {
		return "", fmt.Errorf("nostrtransport: no blossom servers configured")
	}
	var lastErr error
	for _, s := range t.cfg.BlossomServers {
		hash, _, err := t.blossom.Put(ctx, s, data)
		if err == nil {
			return hash, nil
		}
		lastErr = err
	}
	return "", lastErr
}

// GetMedia fetches and hash-verifies a blob.
func (t *Transport) GetMedia(ctx context.Context, hash string) ([]byte, error) {
	var lastErr error
	for _, s := range t.cfg.BlossomServers {
		data, err := t.blossom.Get(ctx, s, hash)
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// FetchFile downloads, verifies and decrypts a kind 15 file.
func (t *Transport) FetchFile(ctx context.Context, msg transport.Message) ([]byte, error) {
	if msg.File == nil {
		return nil, fmt.Errorf("nostrtransport: message has no file")
	}
	ciphertext, err := t.blossom.GetURL(ctx, msg.File.URL, msg.File.CipherSHA256)
	if err != nil {
		// Fall back to configured servers by hash.
		ciphertext, err = t.GetMedia(ctx, msg.File.CipherSHA256)
		if err != nil {
			return nil, err
		}
	}
	key, err := hex.DecodeString(msg.File.DecryptionKey)
	if err != nil {
		return nil, err
	}
	nonce, err := hex.DecodeString(msg.File.Nonce)
	if err != nil {
		return nil, err
	}
	return nostr.DecryptFile(ciphertext, key, nonce, msg.File.CipherSHA256, msg.File.PlainSHA256)
}

// Redact publishes a kind 5 deletion request for one own rumor and
// tombstones it locally. Best effort: relays and recipients may
// keep copies.
func (t *Transport) Redact(ctx context.Context, eventID string) error {
	ev, err := nostr.BuildDeleteEvent(t.cfg.Key, eventID, nostr.KindRumor, t.nowUnix())
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.cursor.Tombstones = appendBounded(t.cursor.Tombstones, eventID)
	cur := t.cursor
	t.mu.Unlock()
	if err := t.store.saveCursor(cur); err != nil {
		return err
	}
	var firstErr error
	anyOK := false
	for _, url := range t.cfg.WriteRelays {
		res, err := t.clientFor(url).Publish(ctx, ev)
		if err == nil && res.Stored() {
			anyOK = true
		} else if firstErr == nil {
			firstErr = err
		}
	}
	if !anyOK && firstErr != nil {
		return firstErr
	}
	if !anyOK {
		return fmt.Errorf("nostrtransport: deletion request not accepted anywhere")
	}
	return nil
}
