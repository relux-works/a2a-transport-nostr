package relay_test

import (
	"context"
	"testing"
	"time"

	"github.com/relux-works/a2a-transport-nostr/nostr"
	"github.com/relux-works/a2a-transport-nostr/relay"
	"github.com/relux-works/a2a-transport-nostr/testrelay"
)

// TestPublishDuplicateClassification proves an OK false with a
// "duplicate:" reason classifies as stored (the relay already
// holds the event), while other rejections do not.
func TestPublishDuplicateClassification(t *testing.T) {
	r, err := testrelay.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	key, _ := nostr.GeneratePrivKey()
	ev := &nostr.Event{CreatedAt: time.Now().Unix(), Kind: 1,
		Tags: [][]string{}, Content: "dup check"}
	if err := key.SignEvent(ev); err != nil {
		t.Fatal(err)
	}
	c := &relay.Client{URL: r.URL}
	defer c.Close()
	ctx := context.Background()
	first, err := c.Publish(ctx, ev)
	if err != nil || !first.Accepted || !first.Stored() {
		t.Fatalf("first publish = %+v %v", first, err)
	}
	second, err := c.Publish(ctx, ev)
	if err != nil {
		t.Fatal(err)
	}
	if second.Accepted || !second.Duplicate || !second.Stored() {
		t.Fatalf("duplicate publish = %+v, want Duplicate stored", second)
	}

	rej, err := testrelay.StartWithOptions(testrelay.Options{OKMode: "reject"})
	if err != nil {
		t.Fatal(err)
	}
	defer rej.Close()
	c2 := &relay.Client{URL: rej.URL}
	defer c2.Close()
	res, err := c2.Publish(ctx, ev)
	if err != nil || res.Stored() || res.Duplicate {
		t.Fatalf("rejected publish = %+v %v, want not stored", res, err)
	}
}
