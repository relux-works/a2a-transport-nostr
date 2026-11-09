package nostrtransport

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	seam "github.com/relux-works/a2a-swarm/transport"
	"relux.works/a2a-transport-nostr/nostr"
	"relux.works/a2a-transport-nostr/relay"
)

// Explicit To sends once to B and self, never C; the empty-To neighbor reaches
// the full conversation. A restart preserves the restricted delivery journal.
func TestSeamExplicitRecipients(t *testing.T) {
	w := newSeamWorld(t)
	req := SendRequest{Conversation: w.conv, IdempotencyKey: "explicit", Message: Message{Text: "restricted", To: []PrincipalID{PrincipalID(w.b.core.Identity()), PrincipalID(w.b.core.Identity())}}}
	first, e := w.a.Send(context.Background(), req)
	if e != nil || first.Outcome != ACK {
		t.Fatal("explicit send failed", e)
	}
	for i, a := range []*Adapter{w.a, w.b, w.c} {
		b, e := a.Sync(context.Background(), nil, SyncOptions{Initial: true})
		want := 1
		if i == 2 {
			want = 0
		}
		if e != nil || len(b.Events) != want {
			t.Fatal("explicit To delivered to excluded party or lost self")
		}
	}
	var rec seamSend
	raw, e := readPrivate(filepath.Join(w.a.dir, "seam-send", sendFileName(req.IdempotencyKey)), 4<<20)
	if e != nil {
		t.Fatal(e)
	}
	if json.Unmarshal(raw, &rec) != nil || len(rec.Parts) != 2 {
		t.Fatal("duplicate recipient was another part")
	}
	for _, part := range rec.Parts {
		if w.r.Attempts(part.Wrap.ID) != 1 {
			t.Fatal("duplicate recipient published twice")
		}
	}
	w.a.Close()
	w.a, e = Open(w.configs[0])
	if e != nil {
		t.Fatal(e)
	}
	defer w.a.Close()
	calls := w.r.Calls()
	again, e := w.a.Send(context.Background(), req)
	if e != nil || again != first || w.r.Calls() != calls {
		t.Fatal("restricted restart did not preserve ACK")
	}
	all := mustSend(t, w, "audience", "all")
	b, e := w.c.Sync(context.Background(), nil, SyncOptions{Initial: true})
	if e != nil || len(b.Events) != 1 || b.Events[0].ID != all.Event {
		t.Fatal("empty To did not reach audience")
	}
}

// Every context-bearing operation rejects a pre-canceled call without relay,
// reader or writer effects; a later valid operation still succeeds.
func TestSeamCanceledOperations(t *testing.T) {
	w := newSeamWorld(t)
	id := mustSend(t, w, "valid", "valid").Event
	ref, e := w.a.Upload(context.Background(), strings.NewReader("valid"), MediaMeta{Size: 5})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := w.r.Calls()
	reader := bytes.NewBufferString("unchanged")
	var out bytes.Buffer
	ops := []func() error{
		func() error { _, e := w.a.Self(ctx); return e },
		func() error { _, e := w.a.ConversationCaps(ctx, w.conv); return e },
		func() error { _, e := w.a.Conversation(ctx, string(w.conv)); return e },
		func() error {
			_, e := w.a.Send(ctx, SendRequest{Conversation: w.conv, IdempotencyKey: "canceled"})
			return e
		},
		func() error { _, e := w.a.Sync(ctx, nil, SyncOptions{Initial: true}); return e },
		func() error { _, e := w.a.History(ctx, w.conv, nil, 1); return e },
		func() error { _, e := w.a.Event(ctx, w.conv, id); return e },
		func() error { _, e := w.a.Members(ctx, w.conv); return e },
		func() error { _, e := w.a.Upload(ctx, reader, MediaMeta{}); return e },
		func() error { _, e := w.a.Download(ctx, ref, &out, 5); return e },
	}
	for i, op := range ops {
		if seam.Code(op()) != seam.Unavailable {
			t.Fatalf("canceled operation %d not unavailable", i)
		}
	}
	if calls != w.r.Calls() || reader.String() != "unchanged" || out.Len() != 0 {
		t.Fatal("canceled operation had I/O effects")
	}
	if _, e = os.Stat(filepath.Join(w.a.dir, "seam-send", sendFileName("canceled"))); !os.IsNotExist(e) {
		t.Fatal("canceled send persisted")
	}
	mustSend(t, w, "valid-after", "valid")
}

// Cancellation after a real self ACK stops future recipient writes and yields
// UNKNOWN without Event; retry sends only the still-pending recipient.
func TestSeamCancelAfterPart(t *testing.T) {
	w := newSeamWorld(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	original := w.a.publishEvent
	w.a.publishEvent = func(ctx context.Context, u string, ev *nostr.Event) (relay.OKResult, error) {
		r, e := original(ctx, u, ev)
		cancel()
		return r, e
	}
	req := SendRequest{Conversation: w.conv, IdempotencyKey: "cancel-mid", Message: Message{Text: "x", To: []PrincipalID{PrincipalID(w.b.core.Identity())}}}
	r, e := w.a.Send(ctx, req)
	if e != nil || r.Outcome != UNKNOWN || r.Event != "" || r.Refusal.Valid() {
		t.Fatal("canceled partial outcome invalid")
	}
	var rec seamSend
	raw, e := readPrivate(filepath.Join(w.a.dir, "seam-send", sendFileName(req.IdempotencyKey)), 4<<20)
	if e != nil {
		t.Fatal(e)
	}
	if json.Unmarshal(raw, &rec) != nil {
		t.Fatal("journal")
	}
	if w.r.Attempts(rec.Parts[w.b.core.Identity()].Wrap.ID) != 0 {
		t.Fatal("canceled pending part reached wire")
	}
	w.a.publishEvent = original
	r, e = w.a.Send(context.Background(), req)
	if e != nil || r.Outcome != ACK {
		t.Fatal("canceled partial retry failed")
	}
	for _, part := range rec.Parts {
		if w.r.Attempts(part.Wrap.ID) != 1 {
			t.Fatal("retry resent acknowledged part")
		}
	}
}

// Incomplete/noncanonical snapshots cannot inherit default identity/version;
// malformed attempts leave the issued History cursor usable.
func TestSeamHistoryMissingFields(t *testing.T) {
	w := newSeamWorld(t)
	mustSend(t, w, "one", "one")
	mustSend(t, w, "two", "two")
	page, e := w.b.History(context.Background(), w.conv, nil, 1)
	if e != nil || len(page.Next) == 0 {
		t.Fatal("history setup", e)
	}
	for _, bad := range []Cursor{Cursor(`{}`), Cursor(`null`), Cursor(`{"IDs":[]}`)} {
		calls := w.r.Calls()
		_, e := w.b.History(context.Background(), w.conv, bad, 1)
		if seam.Code(e) != seam.InvalidCursor || calls != w.r.Calls() {
			t.Fatal("incomplete history cursor accepted or used on wire")
		}
	}
	next, e := w.b.History(context.Background(), w.conv, page.Next, 1)
	if e != nil || len(next.Events) != 1 || next.Events[0].ID == page.Events[0].ID {
		t.Fatal("history cursor damaged")
	}
}

// A seal authenticated as A cannot claim either existing B or C. The entire
// delivered set, sender and marker are checked, not just the injected event ID.
// This supplements (does not repair) upstream #381's narrower impersonation test.
func TestSeamImpersonationNeighbors(t *testing.T) {
	w := newSeamWorld(t)
	good := mustSend(t, w, "good", "valid")
	marker := "untrusted-claim-marker"
	w.inject(t, PrincipalID(w.b.core.Identity()), marker, time.Now())
	w.inject(t, PrincipalID(w.c.core.Identity()), marker, time.Now())
	b, e := w.b.Sync(context.Background(), nil, SyncOptions{Initial: true})
	if e != nil || len(b.Events) != 1 || b.Events[0].ID != good.Event || b.Events[0].Sender != PrincipalID(w.a.core.Identity()) || strings.Contains(b.Events[0].Message.Text, marker) || b.Dropped != 2 {
		t.Fatal("impersonation changed delivery set or sender")
	}
}

// The receive verifier refuses an actually oversized signed wrap before cache
// projection; its original valid wrap remains accepted. This is a verifier
// boundary test, not an upstream large-Raw injection or live-relay claim.
func TestSeamRawLimitPositiveNeighbor(t *testing.T) {
	w := newSeamWorld(t)
	mustSend(t, w, "raw", "valid")
	var wrap *nostr.Event
	for _, ev := range w.r.Events() {
		p, _ := ev.TagFirst("p")
		if p == w.b.core.Identity() {
			wrap = ev
			break
		}
	}
	if wrap == nil {
		t.Fatal("missing wrap")
	}
	if _, e := w.b.verifyWrap(wrap); e != nil {
		t.Fatal("valid wrap refused")
	}
	copy := *wrap
	copy.Tags = append(append([][]string{}, wrap.Tags...), []string{"padding", strings.Repeat("x", maxRawBytes)})
	// Fresh signer requires fresh NIP44 envelope encryption of the same valid seal.
	accepted, e := w.b.verifyWrap(wrap)
	if e != nil {
		t.Fatal(e)
	}
	key, e := nostr.GeneratePrivKey()
	if e != nil {
		t.Fatal(e)
	}
	ck, e := nostr.ConversationKey(key, w.b.core.Identity())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(accepted.Seal)
	copy.Content, e = nostr.EncryptNIP44(string(raw), ck, [32]byte{})
	if e != nil {
		t.Fatal(e)
	}
	if e = key.SignEvent(&copy); e != nil {
		t.Fatal(e)
	}
	if _, e = w.b.verifyWrap(&copy); seam.Code(e) != seam.ContentTooLarge {
		t.Fatal("oversized received wrap not refused at raw bound")
	}
	if _, e = w.b.verifyWrap(wrap); e != nil {
		t.Fatal("valid raw neighbor damaged")
	}
}
