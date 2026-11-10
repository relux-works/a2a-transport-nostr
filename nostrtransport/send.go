package nostrtransport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/relux-works/a2a-transport-nostr/nostr"
	"github.com/relux-works/a2a-transport-nostr/transport"
)

// Send implements transport.Transport.
func (t *Transport) Send(ctx context.Context, conv transport.ConversationID,
	msg transport.Outgoing, idempotencyKey string) (string, transport.AckStatus, error) {
	cj, err := parseConversation(conv)
	if err != nil {
		return "", transport.AckUnknown, err
	}
	if len(msg.Content) > t.cfg.MaxContent {
		return "", transport.AckUnknown, ErrTooLarge
	}
	opts := nostr.RumorOptions{Subject: cj.S, ReplyTo: msg.ReplyTo,
		Root: msg.Root, A2AKind: msg.Kind}
	if msg.Subject != "" {
		opts.Subject = msg.Subject
	}
	rumorHashParts := []string{string(conv), msg.Content, msg.Kind, msg.ReplyTo, msg.Root, msg.Subject}
	return t.sendRumor(ctx, cj, rumorHashParts, idempotencyKey,
		func() (*nostr.Event, error) {
			return nostr.BuildRumor(t.cfg.Key, cj.P, nostr.KindRumor, msg.Content, opts, t.nowUnix())
		})
}

// SendFile encrypts and uploads a file, then sends a kind 15
// message referencing it.
func (t *Transport) SendFile(ctx context.Context, conv transport.ConversationID,
	mime string, data []byte, idempotencyKey string) (string, transport.AckStatus, error) {
	cj, err := parseConversation(conv)
	if err != nil {
		return "", transport.AckUnknown, err
	}
	if len(t.cfg.BlossomServers) == 0 {
		return "", transport.AckUnknown, fmt.Errorf("nostrtransport: no blossom servers configured")
	}
	// The idempotency hash covers the plaintext, so the same key
	// with different data conflicts in sendRumor before anything
	// is built (RN1-01 N3). Encryption and upload happen lazily
	// inside build, which sendRumor only calls on a store miss;
	// a same-data retry replays the stored rumor (pinned key/URL).
	sum := sha256.Sum256(data)
	parts := []string{string(conv), "file", mime, hex.EncodeToString(sum[:])}
	return t.sendRumor(ctx, cj, parts, idempotencyKey,
		func() (*nostr.Event, error) {
			fc, err := nostr.EncryptFile(data)
			if err != nil {
				return nil, err
			}
			var url string
			for _, s := range t.cfg.BlossomServers {
				_, u, err := t.blossom.Put(ctx, s, fc.Ciphertext)
				if err == nil {
					url = u
					break
				}
			}
			if url == "" {
				return nil, fmt.Errorf("nostrtransport: blossom upload failed on all servers")
			}
			opts := nostr.RumorOptions{Subject: cj.S, FileTags: fc.FileTags(url, mime)}
			return nostr.BuildRumor(t.cfg.Key, cj.P, nostr.KindFileMessage, url, opts, t.nowUnix())
		})
}

// sendRumor coalesces concurrent sends under one idempotency
// key (RN1-01 N4): the first caller owns the build/persist/
// publish; concurrent callers wait for its result (or their own
// ctx), and a caller whose content hash differs from the owner's
// conflicts instead of silently taking the owner's ACK.
func (t *Transport) sendRumor(ctx context.Context, cj convJSON, hashParts []string,
	idempotencyKey string, build func() (*nostr.Event, error)) (string, transport.AckStatus, error) {
	if idempotencyKey == "" {
		return "", transport.AckUnknown, fmt.Errorf("nostrtransport: idempotency key required")
	}
	wantHash := contentHash(hashParts...)
	t.sendMu.Lock()
	if c, ok := t.inflight[idempotencyKey]; ok {
		t.sendMu.Unlock()
		if c.hash != wantHash {
			return "", transport.AckUnknown, ErrIdempotencyConflict
		}
		select {
		case <-c.done:
			return c.id, c.ack, c.err
		case <-ctx.Done():
			return "", transport.AckUnknown, ctx.Err()
		}
	}
	c := &sendCall{done: make(chan struct{}), hash: wantHash}
	t.inflight[idempotencyKey] = c
	t.sendMu.Unlock()
	defer func() {
		t.sendMu.Lock()
		delete(t.inflight, idempotencyKey)
		t.sendMu.Unlock()
		close(c.done)
	}()
	c.id, c.ack, c.err = t.sendRumorOnce(ctx, cj, wantHash, idempotencyKey, build)
	return c.id, c.ack, c.err
}

func (t *Transport) sendRumorOnce(ctx context.Context, cj convJSON, wantHash,
	idempotencyKey string, build func() (*nostr.Event, error)) (string, transport.AckStatus, error) {
	rec, found, err := t.store.loadSend(idempotencyKey)
	if err != nil {
		return "", transport.AckUnknown, err
	}
	if found {
		if rec.ContentSHA != wantHash {
			return "", transport.AckUnknown, ErrIdempotencyConflict
		}
		return t.publishRecord(ctx, idempotencyKey, rec)
	}
	rumor, err := build()
	if err != nil {
		return "", transport.AckUnknown, err
	}
	recipients := cj.P // includes self copy
	wraps, err := nostr.WrapForRecipients(t.cfg.Key, rumor, recipients, t.nowUnix())
	if err != nil {
		return "", transport.AckUnknown, err
	}
	rumorRaw, _ := json.Marshal(rumor)
	rec = &sendRecord{
		ContentSHA: wantHash, RumorID: rumor.ID,
		Rumor: rumorRaw, Wraps: map[string]json.RawMessage{},
		Stored: map[string]bool{}, CreatedAt: t.nowUnix(),
	}
	for i, r := range recipients {
		raw, err := json.Marshal(wraps[i])
		if err != nil {
			return "", transport.AckUnknown, err
		}
		rec.Wraps[r] = raw
	}
	// Persist before the first publish attempt.
	if err := t.store.saveSend(idempotencyKey, rec); err != nil {
		return "", transport.AckUnknown, err
	}
	return t.publishRecord(ctx, idempotencyKey, rec)
}

// publishRecord publishes every not-yet-stored wrap to its
// recipient's routes and updates the durable record. ACK requires
// every wrap to reach the quorum; anything else is UNKNOWN.
func (t *Transport) publishRecord(ctx context.Context, idempotencyKey string, rec *sendRecord) (string, transport.AckStatus, error) {
	allStored := true
	// Deterministic recipient order.
	recipients := make([]string, 0, len(rec.Wraps))
	for r := range rec.Wraps {
		recipients = append(recipients, r)
	}
	sortStrings(recipients)
	// Validate the entire persisted batch before publishing or recording progress:
	// a corrupt later recipient must not cause an earlier partial publish.
	parsed := make(map[string]*nostr.Event, len(recipients))
	for _, recipient := range recipients {
		wrap, err := nostr.ParseEvent(rec.Wraps[recipient])
		if err != nil {
			return rec.RumorID, transport.AckUnknown, err
		}
		parsed[recipient] = wrap
	}
	for _, recipient := range recipients {
		wrap := parsed[recipient]
		if rec.Stored[wrap.ID] {
			continue
		}
		acks := 0
		for _, url := range t.resolve(ctx, recipient) {
			c := t.clientFor(url)
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			res, err := c.Publish(pctx, wrap)
			cancel()
			if err == nil && res.Stored() {
				acks++
				if acks >= t.cfg.PublishQuorum {
					break
				}
			}
		}
		if acks >= t.cfg.PublishQuorum {
			rec.Stored[wrap.ID] = true
			// Persist progress best-effort; a crash simply retries
			// the same bytes and the relay answers duplicate.
			_ = t.store.saveSend(idempotencyKey, rec)
		} else {
			allStored = false
		}
	}
	if allStored {
		return rec.RumorID, transport.AckOK, nil
	}
	return rec.RumorID, transport.AckUnknown, nil
}

func sortStrings(xs []string) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j] < xs[j-1]; j-- {
			xs[j], xs[j-1] = xs[j-1], xs[j]
		}
	}
}
