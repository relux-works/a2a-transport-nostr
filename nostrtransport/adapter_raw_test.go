package nostrtransport

import (
	"context"
	"encoding/json"
	"fmt"
	seam "github.com/relux-works/a2a-swarm/transport"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/a2a-transport-nostr/nostr"
	"github.com/relux-works/a2a-transport-nostr/relay"
)

// Publishes an authenticated A-to-B gift wrap of exactly n serialized event
// bytes through the real test relay; only the signed outer padding grows.
func (w *seamWorld) receivedRawAtSize(t *testing.T, n int) EventID {
	t.Helper()
	c, err := w.a.conversation(w.conv)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(wireMessage{Version: 1, Text: fmt.Sprintf("raw-%d", n)})
	at := time.Now().Unix()
	rumor, err := nostr.BuildRumor(w.a.core.cfg.Key, c.P, nostr.KindRumor, string(body), nostr.RumorOptions{}, at)
	if err != nil {
		t.Fatal(err)
	}
	seal, err := nostr.SealRumor(w.a.core.cfg.Key, rumor, w.b.core.Identity(), at)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := nostr.WrapSeal(seal, w.b.core.Identity(), at)
	if err != nil {
		t.Fatal(err)
	}
	key, err := nostr.GeneratePrivKey()
	if err != nil {
		t.Fatal(err)
	}
	ck, err := nostr.ConversationKey(key, w.b.core.Identity())
	if err != nil {
		t.Fatal(err)
	}
	sealJSON, _ := json.Marshal(seal)
	wrap.Content, err = nostr.EncryptNIP44(string(sealJSON), ck, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	wrap.CreatedAt = at
	wrap.Tags = append(wrap.Tags, []string{"padding", ""})
	if err = key.SignEvent(wrap); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(wrap)
	if n < len(raw) {
		t.Fatal("requested size cannot contain an authenticated wrap")
	}
	wrap.Tags[len(wrap.Tags)-1][1] = strings.Repeat("x", n-len(raw))
	if err = key.SignEvent(wrap); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(wrap)
	if len(raw) != n {
		t.Fatalf("wire size=%d want=%d", len(raw), n)
	}
	dm, err := nostr.UnwrapDM(wrap, w.b.core.cfg.Key)
	if err != nil || dm.SenderHex != w.a.core.Identity() || dm.Rumor.ID != rumor.ID {
		t.Fatal("authentication control failed", err)
	}
	client := &relay.Client{URL: w.r.URL}
	defer client.Close()
	if result, err := client.Publish(context.Background(), wrap); err != nil || !result.Accepted {
		t.Fatal("real relay publication failed", err)
	}
	t.Logf("authenticated event bytes=%d; relay accepted", len(raw))
	return EventID(rumor.ID)
}

// A signed oversized wrap between valid neighbors must not poison repeated
// Sync/History scans, enter the cache, or change the nil-Raw projection.
func TestSeamOversizedMailbox(t *testing.T) {
	w := newSeamWorld(t)
	before := mustSend(t, w, "before", "before")
	over := w.receivedRawAtSize(t, seam.MaxRawBytes+1)
	after := mustSend(t, w, "after", "after")
	check := func(events []Event, dropped int) {
		t.Helper()
		if len(events) != 2 || dropped != 1 {
			t.Fatalf("oversized mailbox lost neighbors or drop accounting: events=%d dropped=%d", len(events), dropped)
		}
		seen := map[EventID]bool{}
		for _, ev := range events {
			seen[ev.ID] = true
			if ev.Raw != nil {
				t.Fatal("read exposed Raw")
			}
		}
		if !seen[before.Event] || !seen[after.Event] || seen[over] {
			t.Fatal("oversized mailbox changed event set")
		}
	}
	for i := 0; i < 3; i++ {
		b, err := w.b.Sync(context.Background(), nil, SyncOptions{Initial: true})
		if err != nil || len(b.Gaps) != 0 {
			t.Fatalf("oversized mailbox caused gap: err=%v gaps=%v", err, b.Gaps)
		}
		check(b.Events, b.Dropped)
		p, err := w.b.History(context.Background(), w.conv, nil, 10)
		if err != nil {
			t.Fatal("oversized mailbox poisoned History", err)
		}
		check(p.Events, p.Dropped)
	}
	if _, err := w.b.Event(context.Background(), w.conv, over); seam.Code(err) != seam.InvalidReference {
		t.Fatal("oversized Event accepted")
	}
	if _, err := os.Stat(filepath.Join(w.b.dir, "seam-events", string(over)+".json")); !os.IsNotExist(err) {
		t.Fatal("oversized event cached")
	}
	for _, id := range []EventID{before.Event, after.Event} {
		ev, err := w.b.Event(context.Background(), w.conv, id)
		if err != nil || ev.ID != id || ev.Raw != nil {
			t.Fatal("valid direct Event changed")
		}
	}
}

// Above the documented drain ceiling remains honest loss, never a completed
// dropped event or a successful history scan. The prior cached neighbor survives.
func TestSeamAboveDrainCeiling(t *testing.T) {
	w := newSeamWorld(t)
	good := mustSend(t, w, "good", "valid")
	over := w.receivedRawAtSize(t, relay.MaxDrainBytes+1)
	b, err := w.b.Sync(context.Background(), nil, SyncOptions{Initial: true})
	if err != nil || b.Dropped != 0 || len(b.Gaps) == 0 || b.Gaps[0].Reason != "relay_unreachable" || len(b.Events) != 1 || b.Events[0].ID != good.Event {
		t.Fatal("above drain ceiling did not report honest gap")
	}
	if _, err = w.b.History(context.Background(), w.conv, nil, 10); seam.Code(err) != seam.Unavailable {
		t.Fatal("above drain ceiling claimed complete History")
	}
	if _, err = w.b.Event(context.Background(), w.conv, over); seam.Code(err) != seam.InvalidReference {
		t.Fatal("above drain ceiling Event accepted")
	}
	if _, err = os.Stat(filepath.Join(w.b.dir, "seam-events", string(over)+".json")); !os.IsNotExist(err) {
		t.Fatal("above drain ceiling cached")
	}
}

// Conformance must exercise the actual Raw receive hook; removing it cannot
// silently restore the previous optional skip.
func TestConformanceRawHookPresent(t *testing.T) {
	if upstreamFixture(t).ReceivedRawAtSize == nil {
		t.Fatal("missing ReceivedRawAtSize hook")
	}
}
