package nostrtransport

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/relux-works/a2a-transport-nostr/nostr"
	"github.com/relux-works/a2a-transport-nostr/relay"
)

const seamSeenLimit = 4096

// Checkpoint is local window bookkeeping; REQ.Since filters event.created_at.
// Events published later can be timestamped up to 48h before this checkpoint.
type seamCursor struct {
	Version    int              `json:"v"`
	Transport  string           `json:"transport"`
	Identity   string           `json:"identity"`
	Checkpoint int64            `json:"checkpoint"`
	Relays     []string         `json:"relays"`
	Seen       map[string]int64 `json:"seen"`   // verified wrap IDs -> wrap created_at
	Rumors     map[string]int64 `json:"rumors"` // logical IDs -> latest copy's wrap time
}
type savedEvent struct {
	ID           EventID        `json:"id"`
	Conversation ConversationID `json:"conversation"`
	Sender       PrincipalID    `json:"sender"`
	Time         int64          `json:"time"`
	Message      wireMessage    `json:"message"`
	// Persist exact authenticated rumor for offline cache integrity validation.
	Rumor *nostr.Event `json:"rumor"`
	Seal  *nostr.Event `json:"seal"`
	Wrap  *nostr.Event `json:"wrap"`
}

func (s savedEvent) event() Event {
	return Event{ID: s.ID, Conversation: s.Conversation, Sender: s.Sender, Time: time.Unix(s.Time, 0), Message: fromWire(s.Message)}
}
func (a *Adapter) readCursor(raw Cursor) (seamCursor, error) {
	urls := union(a.core.cfg.ReadRelays, a.core.cfg.DMRelays)
	c := seamCursor{Version: 1, Transport: "nostr", Identity: a.core.Identity(), Checkpoint: a.now().Unix(), Relays: urls, Seen: map[string]int64{}, Rumors: map[string]int64{}}
	if len(raw) == 0 {
		return c, nil
	}
	c = seamCursor{}
	if len(raw) > 1<<20 || strictJSON(raw, &c) != nil || c.Version != 1 || c.Transport != "nostr" || c.Identity != a.core.Identity() || c.Checkpoint < 0 || c.Checkpoint > a.now().Unix()+futureSkewSeconds || c.Seen == nil || c.Rumors == nil || len(c.Seen) > seamSeenLimit || len(c.Rumors) > seamSeenLimit || len(c.Relays) > 16 {
		return c, seamError("invalid_cursor")
	}
	b, _ := json.Marshal(c.Relays)
	if _, e := settingURLs(string(b), true); e != nil {
		return c, seamError("invalid_cursor")
	}
	for _, set := range []map[string]int64{c.Seen, c.Rumors} {
		for id, at := range set {
			if !hexID(id) || at < 0 || at > c.Checkpoint+futureSkewSeconds {
				return c, seamError("invalid_cursor")
			}
		}
	}
	return c, nil
}
func (a *Adapter) Sync(ctx context.Context, from Cursor, opt SyncOptions) (Batch, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.syncLocked(ctx, from, opt)
}
func (a *Adapter) syncLocked(ctx context.Context, from Cursor, opt SyncOptions) (Batch, error) {
	if a.closed || ctx.Err() != nil {
		return Batch{}, seamError("unavailable")
	}
	c, e := a.readCursor(from)
	if e != nil {
		return Batch{}, e
	}
	if len(from) == 0 && !opt.Initial {
		return Batch{}, seamError("invalid_cursor")
	}
	if opt.Timeout < 0 {
		return Batch{}, seamError("invalid_reference")
	}
	limit := a.batchLimit
	out := Batch{}
	reasons := map[string]bool{}
	urls := union(a.core.cfg.ReadRelays, a.core.cfg.DMRelays)
	old, _ := json.Marshal(c.Relays)
	nextRelays, _ := json.Marshal(urls)
	if string(old) != string(nextRelays) {
		reasons["relay_set_changed"] = true
	}
	now := a.now().Unix()
	if now-c.Checkpoint > syncWindow {
		reasons["window_exceeded"] = true
	}
	since := max(int64(0), c.Checkpoint-syncWindow)
	allOK := true
	for _, u := range urls {
		call, cancel := context.WithTimeout(ctx, 3*time.Second)
		evs, dropped, err := a.core.clientFor(u).QueryBoundedWithDrops(call, "seam-sync", relay.Filter{Kinds: []int{nostr.KindGiftWrap}, PTags: []string{a.core.Identity()}, Since: &since, Limit: seamSeenLimit}, seamSeenLimit)
		cancel()
		out.Dropped += dropped
		a.dropped += uint64(dropped)
		if err != nil {
			allOK = false
			if errors.Is(err, relay.ErrQueryLimit) {
				reasons["timeline_limited"] = true
			} else {
				reasons["relay_unreachable"] = true
			}
		}
		// Hitting a relay-enforced bound is possibly truncated even if EOSE arrived.
		if len(evs) >= seamSeenLimit {
			reasons["timeline_limited"] = true
			allOK = false
		}
		for _, wrap := range evs {
			if _, ok := c.Seen[wrap.ID]; ok {
				continue
			}
			if len(out.Events) >= limit {
				reasons["timeline_limited"] = true
				allOK = false
				break
			}
			s, err := a.verifyWrap(wrap)
			if err != nil {
				a.dropped++
				out.Dropped++
				continue
			}
			if wrap.CreatedAt < since {
				reasons["window_exceeded"] = true
				continue
			}
			if len(c.Seen) >= seamSeenLimit || len(c.Rumors) >= seamSeenLimit {
				reasons["timeline_limited"] = true
				allOK = false
				break
			}
			if _, ok := c.Rumors[string(s.ID)]; ok {
				c.Seen[wrap.ID] = wrap.CreatedAt
				c.Rumors[string(s.ID)] = max(c.Rumors[string(s.ID)], wrap.CreatedAt)
				continue
			}
			raw, _ := marshalEnvelope(s)
			if writeFileFsync(filepath.Join(a.dir, "seam-events"), string(s.ID)+".json", raw) != nil {
				return Batch{}, seamError("unavailable")
			}
			c.Seen[wrap.ID] = wrap.CreatedAt
			c.Rumors[string(s.ID)] = wrap.CreatedAt
			out.Events = append(out.Events, s.event())
		}
	}
	if ctx.Err() != nil {
		return Batch{}, seamError("unavailable")
	}
	if allOK {
		c.Checkpoint = now
	}
	c.Relays = urls
	floor := c.Checkpoint - syncWindow
	for _, set := range []map[string]int64{c.Seen, c.Rumors} {
		for id, at := range set {
			if at < floor {
				delete(set, id)
			}
		}
	}
	// Relay/window loss is identity-wide; also identify previously verified
	// conversations so a conversation consumer can observe its possible loss.
	known := map[string]bool{}
	if len(reasons) > 0 {
		entries, err := os.ReadDir(filepath.Join(a.dir, "seam-events"))
		if err != nil || len(entries) > seamSeenLimit {
			return Batch{}, seamError("unavailable")
		}
		for _, entry := range entries {
			n := entry.Name()
			if len(n) != 69 || n[64:] != ".json" {
				return Batch{}, seamError("unavailable")
			}
			saved, err := a.loadEvent(EventID(n[:64]))
			if err != nil {
				return Batch{}, err
			}
			known[string(saved.Conversation)] = true
		}
	}
	// Empty conversation additionally covers conversations not yet observed.
	for _, reason := range sortedKeys(reasons) {
		out.Gaps = append(out.Gaps, Gap{Reason: GapReason(reason)})
		for _, conv := range sortedKeys(known) {
			out.Gaps = append(out.Gaps, Gap{Conversation: ConversationID(conv), Reason: GapReason(reason)})
		}
	}
	raw, _ := json.Marshal(c)
	out.Next = Cursor(raw)
	// Cursor belongs to the caller's mailbox transaction: never adopt a newer
	// internal cursor on restart and skip events not yet committed by that caller.
	return out, nil
}
func (a *Adapter) verifyWrap(wrap *nostr.Event) (savedEvent, error) {
	var s savedEvent
	raw, err := json.Marshal(wrap)
	if err != nil || len(raw) > maxRawBytes {
		return s, seamError("content_too_large")
	}
	if wrap == nil || wrap.CreatedAt < 0 || wrap.CreatedAt > a.now().Unix()+futureSkewSeconds {
		return s, seamError("unauthenticated")
	}
	dm, e := nostr.UnwrapDM(wrap, a.core.cfg.Key)
	if e != nil {
		return s, seamError("unauthenticated")
	}
	r := dm.Rumor
	if r.CreatedAt < 0 || r.CreatedAt > a.now().Unix()+futureSkewSeconds {
		return s, seamError("unauthenticated")
	}
	p := []string{}
	for _, tag := range r.Tags {
		if len(tag) >= 2 && tag[0] == "p" {
			p = append(p, tag[1])
		}
	}
	if !contains(p, a.core.Identity()) || !contains(p, dm.SenderHex) {
		return s, seamError("unauthenticated")
	}
	subject, _ := r.TagFirst("subject")
	conv, _ := json.Marshal(convJSON{P: nostr.SortedUnique(p), S: subject})
	if _, e := a.conversation(ConversationID(conv)); e != nil {
		return s, e
	}
	body := r.Content
	if r.Kind == nostr.KindFileMessage {
		body, _ = r.TagFirst("a2a-message")
	}
	var w wireMessage
	if strictJSON([]byte(body), &w) != nil || w.Version != 1 {
		return s, seamError("invalid_reference")
	}
	normalized, e := toWire(fromWire(w))
	if e != nil {
		return s, e
	}
	for _, to := range normalized.To {
		if !contains(p, string(to)) {
			return s, seamError("invalid_reference")
		}
	}
	if r.Kind == nostr.KindFileMessage {
		if len(w.Media) != 1 {
			return s, seamError("invalid_reference")
		}
		m, e := decodeMedia(w.Media[0])
		if e != nil {
			return s, e
		}
		u, mime, k, n, x, ox, ok := nostr.ParseFileTags(r)
		if !ok || u != m.URL || mime != m.MIME || k != m.Key || n != m.Nonce || x != m.CipherSHA || ox != m.PlainSHA {
			return s, seamError("invalid_reference")
		}
	} else if len(w.Media) != 0 {
		return s, seamError("invalid_reference")
	}
	s = savedEvent{ID: EventID(r.ID), Conversation: ConversationID(conv), Sender: PrincipalID(dm.SenderHex), Time: r.CreatedAt, Message: w, Rumor: r, Seal: dm.Seal, Wrap: wrap}
	return s, nil
}
func (a *Adapter) loadEvent(id EventID) (savedEvent, error) {
	var s savedEvent
	if !hexID(string(id)) {
		return s, seamError("invalid_reference")
	}
	raw, e := readPrivate(filepath.Join(a.dir, "seam-events", string(id)+".json"), 256<<10)
	if e != nil || strictJSON(raw, &s) != nil {
		return s, seamError("unavailable")
	}
	verified, e := a.verifyWrap(s.Wrap)
	if e != nil {
		return s, e
	}
	x, _ := json.Marshal(s)
	y, _ := json.Marshal(verified)
	if string(x) != string(y) || s.ID != id {
		return s, seamError("unavailable")
	}
	return s, nil
}
func (a *Adapter) Event(ctx context.Context, c ConversationID, id EventID) (Event, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || ctx.Err() != nil {
		return Event{}, seamError("unavailable")
	}
	if _, e := a.conversation(c); e != nil {
		return Event{}, e
	}
	if !hexID(string(id)) {
		return Event{}, seamError("invalid_reference")
	}
	s, e := a.loadEvent(id)
	if e != nil {
		if _, err := a.syncLocked(ctx, nil, SyncOptions{Initial: true}); err != nil {
			return Event{}, err
		}
		s, e = a.loadEvent(id)
	}
	if e != nil || s.Conversation != c {
		return Event{}, seamError("invalid_reference")
	}
	return s.event(), nil
}

type historyCursor struct {
	Version      int
	Identity     string
	Conversation ConversationID
	IDs          []EventID
	Offset       int
}

func (a *Adapter) History(ctx context.Context, c ConversationID, page Cursor, limit int) (Page, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || ctx.Err() != nil {
		return Page{}, seamError("unavailable")
	}
	if _, e := a.conversation(c); e != nil {
		return Page{}, e
	}
	if limit < 1 {
		return Page{}, seamError("invalid_reference")
	}
	limit = min(limit, 1024)
	dropped := 0
	h := historyCursor{Version: 1, Identity: a.core.Identity(), Conversation: c}
	if len(page) > 0 {
		h = historyCursor{}
		if len(page) > 1<<20 || strictJSON(page, &h) != nil || h.Version != 1 || h.Identity != a.core.Identity() || h.Conversation != c || h.Offset < 1 || h.Offset >= len(h.IDs) || h.IDs == nil || len(h.IDs) > seamSeenLimit {
			return Page{}, seamError("invalid_cursor")
		}
		for i, id := range h.IDs {
			if !hexID(string(id)) || (i > 0 && h.IDs[i-1] >= id) {
				return Page{}, seamError("invalid_cursor")
			}
		}
	} else {
		batch, e := a.syncLocked(ctx, nil, SyncOptions{Initial: true})
		if e != nil {
			return Page{}, e
		}
		dropped = batch.Dropped
		if len(batch.Gaps) > 0 {
			return Page{}, seamError("unavailable")
		}
		entries, e := os.ReadDir(filepath.Join(a.dir, "seam-events"))
		if e != nil || len(entries) > seamSeenLimit {
			return Page{}, seamError("unavailable")
		}
		for _, entry := range entries {
			n := entry.Name()
			if len(n) != 69 || n[64:] != ".json" {
				return Page{}, seamError("unavailable")
			}
			s, e := a.loadEvent(EventID(n[:64]))
			if e != nil {
				return Page{}, e
			}
			if s.Conversation == c {
				h.IDs = append(h.IDs, s.ID)
			}
		}
		sort.Slice(h.IDs, func(i, j int) bool { return h.IDs[i] < h.IDs[j] })
	}
	out := Page{Dropped: dropped}
	for h.Offset < len(h.IDs) && len(out.Events) < limit {
		s, e := a.loadEvent(h.IDs[h.Offset])
		if e != nil || s.Conversation != c {
			return Page{}, seamError("invalid_cursor")
		}
		out.Events = append(out.Events, s.event())
		h.Offset++
	}
	if h.Offset < len(h.IDs) {
		out.Next, _ = json.Marshal(h)
	}
	return out, nil
}
