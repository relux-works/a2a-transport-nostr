package nostrtransport

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/relux-works/a2a-transport-nostr/nostr"
)

type wireMessage struct {
	Version    int                        `json:"v"`
	Kind       string                     `json:"kind,omitempty"`
	Text       string                     `json:"text"`
	To         []PrincipalID              `json:"to,omitempty"`
	Re         EventID                    `json:"re,omitempty"`
	Thread     EventID                    `json:"thread,omitempty"`
	Media      []json.RawMessage          `json:"media,omitempty"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

func toWire(m Message) (wireMessage, error) {
	w := wireMessage{Version: 1, Kind: m.Kind, Text: m.Text, To: m.To, Re: m.Re, Thread: m.Thread, Extensions: m.Extensions}
	if !utf8.ValidString(m.Text) || len(m.Text) > seamMaxContent {
		return w, seamError("content_too_large")
	}
	if len(m.Kind) > 64 || !utf8.ValidString(m.Kind) || len(m.To) > maxParties || len(m.Attachments) > 1 {
		return w, seamError("invalid_reference")
	}
	for _, id := range []EventID{m.Re, m.Thread} {
		if id != "" && !hexID(string(id)) {
			return w, seamError("invalid_reference")
		}
	}
	for _, ref := range m.Attachments {
		raw := []byte(ref.Opaque())
		if _, e := decodeMedia(raw); e != nil {
			return w, e
		}
		w.Media = append(w.Media, json.RawMessage(raw))
	}
	extra, e := json.Marshal(m.Extensions)
	if e != nil || len(extra) > 1024 {
		return w, seamError("content_too_large")
	}
	for k := range m.Extensions {
		if len(k) > 128 || !utf8.ValidString(k) {
			return w, seamError("invalid_reference")
		}
	}
	raw, err := json.Marshal(w)
	if err != nil || len(raw) > seamMaxContent {
		return w, seamError("content_too_large")
	}
	return w, nil
}
func fromWire(w wireMessage) Message {
	m := Message{Kind: w.Kind, Text: w.Text, To: w.To, Re: w.Re, Thread: w.Thread, Extensions: w.Extensions}
	for _, r := range w.Media {
		m.Attachments = append(m.Attachments, mediaRef(string(r)))
	}
	return m
}
func hexID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

type seamPart struct {
	Seal    *nostr.Event    `json:"seal"`
	Wrap    *nostr.Event    `json:"wrap"`
	Relays  []string        `json:"relays"`
	Ack     bool            `json:"ack"`
	Refused map[string]bool `json:"refused"`
	// Uncertain is sticky for any attempt without a definitive original reply.
	// A later rejection cannot prove that such an earlier attempt was not stored.
	Uncertain map[string]bool `json:"uncertain"`
}
type seamSend struct {
	Checksum     string               `json:"checksum"`
	Version      int                  `json:"v"`
	Identity     string               `json:"identity"`
	Hash         string               `json:"hash"`
	Conversation ConversationID       `json:"conversation"`
	Rumor        *nostr.Event         `json:"rumor"`
	Parts        map[string]*seamPart `json:"parts"`
}

func (a *Adapter) Send(ctx context.Context, req SendRequest) (SendResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || ctx.Err() != nil {
		return SendResult{}, seamError("unavailable")
	}
	c, e := a.conversation(req.Conversation)
	if e != nil {
		return SendResult{}, e
	}
	if len(req.IdempotencyKey) == 0 || len(req.IdempotencyKey) > 1024 {
		return SendResult{}, seamError("invalid_reference")
	}
	w, e := toWire(req.Message)
	if e != nil {
		return SendResult{}, e
	}
	for _, to := range w.To {
		if !contains(c.P, string(to)) {
			return SendResult{}, seamError("invalid_reference")
		}
	}
	canonical, _ := json.Marshal(struct {
		Conversation ConversationID
		Message      wireMessage
	}{req.Conversation, w})
	targets := deliveryTargets(c.P, w.To, a.core.Identity())
	hash := digest(canonical)
	name := sendFileName(req.IdempotencyKey)
	raw, err := readPrivate(filepath.Join(a.dir, "seam-send", name), 4<<20)
	var rec seamSend
	if err == nil {
		if strictJSON(raw, &rec) != nil || a.checkRecord(&rec) != nil {
			return SendResult{Outcome: UNKNOWN}, nil
		}
		if rec.Hash != hash {
			return SendResult{}, seamError("invalid_reference")
		}
	} else if !os.IsNotExist(err) {
		return SendResult{Outcome: UNKNOWN}, nil
	} else {
		body, _ := json.Marshal(w)
		kind := nostr.KindRumor
		content := string(body)
		opts := nostr.RumorOptions{Subject: c.S, ReplyTo: string(w.Re), Root: string(w.Thread), A2AKind: w.Kind}
		if len(w.Media) == 1 {
			m, _ := decodeMedia(w.Media[0])
			kind = nostr.KindFileMessage
			content = m.URL
			opts.FileTags = m.tags()
			opts.FileTags = append(opts.FileTags, []string{"a2a-message", string(body)})
		}
		rumor, e := nostr.BuildRumor(a.core.cfg.Key, c.P, kind, content, opts, a.now().Unix())
		if e != nil {
			return SendResult{}, seamError("invalid_reference")
		}
		rumor.Tags = append(rumor.Tags, []string{"a2a-txn", digest([]byte(req.IdempotencyKey))})
		rumor.ID = rumor.ComputeID()
		rec = seamSend{Version: 1, Identity: a.core.Identity(), Hash: hash, Conversation: req.Conversation, Rumor: rumor, Parts: map[string]*seamPart{}}
		// Build/size-check every cryptographic layer before any discovery or publish.
		for _, p := range targets {
			seal, e := nostr.SealRumor(a.core.cfg.Key, rumor, p, a.now().Unix())
			if e != nil {
				return SendResult{}, seamError("content_too_large")
			}
			wrap, e := nostr.WrapSeal(seal, p, a.now().Unix())
			if e != nil {
				return SendResult{}, seamError("content_too_large")
			}
			rec.Parts[p] = &seamPart{Seal: seal, Wrap: wrap, Refused: map[string]bool{}, Uncertain: map[string]bool{}}
		}
		for _, p := range targets {
			routeBytes, _ := json.Marshal(a.core.resolve(ctx, p))
			routes, e := settingURLs(string(routeBytes), true)
			if e != nil || len(routes) == 0 {
				return SendResult{}, seamError("unavailable")
			}
			rec.Parts[p].Relays = routes
		}
		if err := a.saveRecord(name, &rec); err != nil {
			return SendResult{}, seamError("unavailable")
		}
	}
	return a.publish(ctx, name, &rec, targets), nil
}
func (a *Adapter) saveRecord(name string, r *seamSend) error {
	r.Checksum = ""
	unsigned, e := json.Marshal(r)
	if e != nil {
		return e
	}
	r.Checksum = digest(unsigned)
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	return writeFileFsync(filepath.Join(a.dir, "seam-send"), name, b)
}
func (a *Adapter) checkRecord(r *seamSend) error {
	copy := *r
	copy.Checksum = ""
	raw, _ := json.Marshal(&copy)
	if r.Checksum != digest(raw) {
		return seamError("unavailable")
	}
	c, e := a.conversation(r.Conversation)
	if e != nil {
		return e
	}
	if r.Version != 1 || r.Identity != a.core.Identity() || !hexID(r.Hash) || r.Rumor == nil || r.Rumor.PubKey != r.Identity || !r.Rumor.CheckID() || r.Rumor.Sig != "" {
		return seamError("unavailable")
	}
	for p, v := range r.Parts {
		if !contains(c.P, p) {
			return seamError("unavailable")
		}
		if v == nil || v.Wrap == nil || v.Seal == nil || len(v.Relays) == 0 || v.Refused == nil || v.Uncertain == nil {
			return seamError("unavailable")
		}
		if nostr.VerifySignature(v.Wrap) != nil || nostr.VerifySignature(v.Seal) != nil || v.Seal.PubKey != r.Identity {
			return seamError("unavailable")
		}
		target, _ := v.Wrap.TagFirst("p")
		if target != p {
			return seamError("unavailable")
		}
	}
	if r.Parts[r.Identity] == nil {
		return seamError("unavailable")
	}
	self, err := a.verifyWrap(r.Parts[r.Identity].Wrap)
	if err != nil || self.ID != EventID(r.Rumor.ID) || self.Conversation != r.Conversation {
		return seamError("unavailable")
	}
	rumorRaw, _ := json.Marshal(r.Rumor)
	targets := deliveryTargets(c.P, self.Message.To, r.Identity)
	if len(targets) != len(r.Parts) {
		return seamError("unavailable")
	}
	for _, p := range targets {
		part := r.Parts[p]
		if part == nil {
			return seamError("unavailable")
		}
		ck, err := nostr.ConversationKey(a.core.cfg.Key, p)
		if err != nil {
			return seamError("unavailable")
		}
		plain, err := nostr.DecryptNIP44(part.Seal.Content, ck)
		if err != nil || plain != string(rumorRaw) {
			return seamError("unavailable")
		}
	}
	return nil
}
func (a *Adapter) publish(ctx context.Context, name string, rec *seamSend, targets []string) SendResult {
	result := SendResult{Outcome: UNKNOWN}
	all := true
	definite := true
	for _, p := range targets {
		part := rec.Parts[p]
		if part.Ack {
			definite = false
			continue
		}
		for _, u := range part.Relays {
			if ctx.Err() != nil {
				return result
			}
			if part.Refused[u] {
				continue
			}
			// Persist uncertainty BEFORE I/O; process death cannot turn a lost ACK into
			// proof of refusal. A definitive first response can clear this attempt only.
			prior := part.Uncertain[u]
			part.Uncertain[u] = true
			if a.saveRecord(name, rec) != nil {
				return result
			}
			call, cancel := context.WithTimeout(ctx, 3*time.Second)
			ok, e := a.publishEvent(call, u, part.Wrap)
			cancel()
			if e == nil && ok.Original && ok.Stored() {
				part.Ack = true
				delete(part.Uncertain, u)
			} else if e == nil && ok.Original && definiteReason(ok.Reason) && !prior {
				delete(part.Uncertain, u)
				part.Refused[u] = true
			}
			if a.saveRecord(name, rec) != nil {
				return result
			}
			if part.Ack {
				break
			}
		}
		if part.Ack {
			definite = false
		}
		if !part.Ack {
			all = false
			refused := len(part.Relays) > 0
			for _, u := range part.Relays {
				refused = refused && part.Refused[u] && !part.Uncertain[u]
			}
			definite = definite && refused
		}
	}
	if all {
		result.Outcome = ACK
		result.Event = EventID(rec.Rumor.ID)
	} else if definite {
		result.Outcome = REFUSED
		result.Refusal = newRefusal("refused")
	}
	return result
}
func definiteReason(reason string) bool {
	for _, prefix := range []string{"blocked:", "invalid:", "restricted:"} {
		if strings.HasPrefix(reason, prefix) {
			return true
		}
	}
	return false
}
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// Preserve explicit-recipient order, always include self, and never send duplicates.
func deliveryTargets(audience []string, to []PrincipalID, self string) []string {
	out := []string{self}
	if len(to) == 0 {
		for _, p := range audience {
			if !contains(out, p) {
				out = append(out, p)
			}
		}
	} else {
		for _, p := range to {
			if !contains(out, string(p)) {
				out = append(out, string(p))
			}
		}
	}
	return out
}
