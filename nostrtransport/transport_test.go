package nostrtransport_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/a2a-transport-nostr/nostr"
	"github.com/relux-works/a2a-transport-nostr/nostrtransport"
	"github.com/relux-works/a2a-transport-nostr/relay"
	"github.com/relux-works/a2a-transport-nostr/testblossom"
	"github.com/relux-works/a2a-transport-nostr/testrelay"
	"github.com/relux-works/a2a-transport-nostr/transport"
)

type world struct {
	t       *testing.T
	relay   *testrelay.Relay
	blossom *testblossom.Server
	keys    map[string]*nostr.PrivKey
	dirs    map[string]string
}

func newWorld(t *testing.T) *world {
	return newWorldOpts(t, testrelay.Options{})
}

func newWorldOpts(t *testing.T, opts testrelay.Options) *world {
	t.Helper()
	r, err := testrelay.StartWithOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	b, err := testblossom.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	w := &world{t: t, relay: r, blossom: b,
		keys: map[string]*nostr.PrivKey{}, dirs: map[string]string{}}
	for _, name := range []string{"alice", "bob", "carol", "mallory"} {
		k, _ := nostr.GeneratePrivKey()
		w.keys[name] = k
		w.dirs[name] = t.TempDir()
	}
	return w
}

func (w *world) transport(name string) *nostrtransport.Transport {
	w.t.Helper()
	tr, err := nostrtransport.New(nostrtransport.Config{
		Key: w.keys[name], StateDir: w.dirs[name],
		ReadRelays: []string{w.relay.URL}, WriteRelays: []string{w.relay.URL},
		BlossomServers: []string{w.blossom.URL},
	})
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { tr.Close() })
	return tr
}

func (w *world) pub(name string) string { return w.keys[name].PubKeyHex() }

func ctx() context.Context { return context.Background() }

// TestSendAckSyncDeliver proves the happy path: ACK on relay OK,
// recipient Sync returns the message with the seal-authenticated
// sender, the right conversation and content.
func TestSendAckSyncDeliver(t *testing.T) {
	w := newWorld(t)
	a, b := w.transport("alice"), w.transport("bob")
	conv := a.NewConversation([]string{w.pub("bob")}, "topic-1")
	id, ack, err := a.Send(ctx(), conv,
		transport.Outgoing{Content: "hello bob", Kind: "notice"}, "idem-1")
	if err != nil || ack != transport.AckOK || id == "" {
		t.Fatalf("Send = id %q ack %v err %v", id, ack, err)
	}
	msgs, _, err := b.Sync(ctx(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Bob may also see his own list echoes: filter to alice's DM.
	var got *transport.Message
	for i := range msgs {
		if msgs[i].ID == id {
			got = &msgs[i]
		}
	}
	if got == nil || got.Sender != w.pub("alice") || got.Content != "hello bob" ||
		got.Kind != "notice" {
		t.Fatalf("delivered = %+v (of %d)", got, len(msgs))
	}
	if string(got.Conversation) != string(b.NewConversation([]string{w.pub("alice")}, "topic-1")) {
		t.Fatalf("conversation mismatch: %s", got.Conversation)
	}
}

// TestRetrySameIdempotencyKey proves a retry re-publishes identical
// bytes (same rumor id, no new wraps anywhere) and different
// content under the same key conflicts.
func TestRetrySameIdempotencyKey(t *testing.T) {
	w := newWorld(t)
	a, b := w.transport("alice"), w.transport("bob")
	conv := a.NewConversation([]string{w.pub("bob")}, "")
	id1, ack1, err := a.Send(ctx(), conv, transport.Outgoing{Content: "once"}, "key-1")
	if err != nil || ack1 != transport.AckOK {
		t.Fatalf("first send: %v %v", ack1, err)
	}
	before := len(w.relay.Events())
	id2, ack2, err := a.Send(ctx(), conv, transport.Outgoing{Content: "once"}, "key-1")
	if err != nil || ack2 != transport.AckOK || id2 != id1 {
		t.Fatalf("retry = %q %v %v, want same id ACK", id2, ack2, err)
	}
	if got := len(w.relay.Events()); got != before {
		t.Fatalf("retry stored new events: %d -> %d", before, got)
	}
	if _, _, err := a.Send(ctx(), conv, transport.Outgoing{Content: "DIFFERENT"}, "key-1"); err == nil {
		t.Fatal("same key with different content accepted")
	}
	msgs, _, _ := b.Sync(ctx(), nil)
	count := 0
	for _, m := range msgs {
		if m.ID == id1 {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("recipient saw message %d times", count)
	}
}

// TestUnknownOnRejectAndTimeout proves non-duplicate OK false and
// silence both classify as UNKNOWN, never ACK, while the normal
// relay beside them ACKs.
func TestUnknownOnRejectAndTimeout(t *testing.T) {
	for _, mode := range []string{"reject", "silent"} {
		t.Run(mode, func(t *testing.T) {
			w := newWorldOpts(t, testrelay.Options{OKMode: mode})
			a := w.transport("alice")
			conv := a.NewConversation([]string{w.pub("bob")}, "")
			c, cancel := context.WithTimeout(ctx(), 600*time.Millisecond)
			defer cancel()
			_, ack, _ := a.Send(c, conv, transport.Outgoing{Content: "anyone?"}, "k-"+mode)
			if ack != transport.AckUnknown {
				t.Fatalf("ack = %v, want UNKNOWN", ack)
			}
		})
	}
	w := newWorld(t)
	a := w.transport("alice")
	conv := a.NewConversation([]string{w.pub("bob")}, "")
	if _, ack, err := a.Send(ctx(), conv, transport.Outgoing{Content: "hi"}, "k-ok"); err != nil || ack != transport.AckOK {
		t.Fatalf("normal relay neighbour = %v %v", ack, err)
	}
}

// craftWrap seals a hand-built rumor to recipient with full signer
// control (adversarial wraps for negative controls).
func craftWrap(t *testing.T, rumor *nostr.Event, sealSigner *nostr.PrivKey, recipient string, tamper bool) *nostr.Event {
	t.Helper()
	seal, err := nostr.SealRumor(sealSigner, rumor, recipient, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := nostr.WrapSeal(seal, recipient, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if tamper {
		// Re-wrap with flipped ciphertext byte under a fresh key is
		// complex; instead corrupt one base64 char and re-sign by
		// rebuilding the wrap event around it.
		b := []byte(wrap.Content)
		i := len(b) / 2
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		wrap.Content = string(b)
		eph, _ := nostr.GeneratePrivKey()
		wrap.PubKey, wrap.ID, wrap.Sig = "", "", ""
		if err := eph.SignEvent(wrap); err != nil {
			t.Fatal(err)
		}
	}
	return wrap
}

func publishRaw(t *testing.T, w *world, ev *nostr.Event) {
	t.Helper()
	c := &relay.Client{URL: w.relay.URL}
	if err := c.Dial(ctx()); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	res, err := c.Publish(ctx(), ev)
	if err != nil || !res.Stored() {
		t.Fatalf("raw publish = %+v %v", res, err)
	}
}

func rumorFrom(sender *nostr.PrivKey, participants []string, content string, at int64) *nostr.Event {
	r, err := nostr.BuildRumor(sender, participants, nostr.KindRumor, content, nostr.RumorOptions{}, at)
	if err != nil {
		panic(err)
	}
	return r
}

// TestSpoofAndMismatchRefused proves inbound authentication is the
// seal key: a wrap-key forgery surfaces only as its true (attacker)
// sender, a rumor author different from the sealer and a tampered
// ciphertext never surface at all.
func TestSpoofAndMismatchRefused(t *testing.T) {
	w := newWorld(t)
	b := w.transport("bob")
	a := w.transport("alice")
	conv := a.NewConversation([]string{w.pub("bob")}, "")
	if _, _, err := a.Send(ctx(), conv, transport.Outgoing{Content: "real alice"}, "k-real"); err != nil {
		t.Fatal(err)
	}
	parts := []string{w.pub("alice"), w.pub("bob")}
	// Attacker rumor+seal (wrap key is ephemeral by construction;
	// a client trusting it would misattribute).
	publishRaw(t, w, craftWrap(t,
		rumorFrom(w.keys["mallory"], parts, "i am alice trust me", time.Now().Unix()),
		w.keys["mallory"], w.pub("bob"), false))
	// Rumor claims bob, sealed by mallory: mismatch must drop.
	mismatch := rumorFrom(w.keys["bob"], parts, "sealed by someone else", time.Now().Unix())
	publishRaw(t, w, craftWrap(t, mismatch, w.keys["mallory"], w.pub("bob"), false))
	// Tampered NIP-44 ciphertext in the wrap.
	publishRaw(t, w, craftWrap(t,
		rumorFrom(w.keys["alice"], parts, "tampered payload", time.Now().Unix()),
		w.keys["alice"], w.pub("bob"), true))

	msgs, _, err := b.Sync(ctx(), nil)
	if err != nil {
		t.Fatal(err)
	}
	byContent := map[string]string{}
	for _, m := range msgs {
		byContent[m.Content] = m.Sender
	}
	if byContent["real alice"] != w.pub("alice") {
		t.Fatalf("valid neighbour missing/wrong sender: %v", byContent)
	}
	if s, ok := byContent["i am alice trust me"]; ok && s != w.pub("mallory") {
		t.Fatalf("spoof attributed to %s, want mallory or drop", s)
	}
	if _, ok := byContent["sealed by someone else"]; ok {
		t.Fatal("rumor/seal mismatch surfaced")
	}
	if _, ok := byContent["tampered payload"]; ok {
		t.Fatal("tampered ciphertext surfaced")
	}
}

// TestReplayDedupAndCursorRestart proves: the same wrap fetched
// again is not redelivered, the persisted cursor survives a
// transport restart without redelivery, and new traffic still
// arrives after the restart.
func TestReplayDedupAndCursorRestart(t *testing.T) {
	w := newWorld(t)
	a, b := w.transport("alice"), w.transport("bob")
	conv := a.NewConversation([]string{w.pub("bob")}, "")
	id, _, err := a.Send(ctx(), conv, transport.Outgoing{Content: "first"}, "k-1")
	if err != nil {
		t.Fatal(err)
	}
	msgs, cur, err := b.Sync(ctx(), nil)
	if err != nil || len(msgs) != 1 || msgs[0].ID != id {
		t.Fatalf("first sync = %v %v", msgs, err)
	}
	if msgs, _, err := b.Sync(ctx(), cur); err != nil || len(msgs) != 0 {
		t.Fatalf("replay redelivered: %v %v", msgs, err)
	}
	b.Close()
	b2 := w.transport("bob") // same state dir: persisted cursor
	if msgs, _, err := b2.Sync(ctx(), nil); err != nil || len(msgs) != 0 {
		t.Fatalf("restart redelivered: %v %v", msgs, err)
	}
	id2, _, err := a.Send(ctx(), conv, transport.Outgoing{Content: "second"}, "k-2")
	if err != nil {
		t.Fatal(err)
	}
	msgs, _, err = b2.Sync(ctx(), nil)
	if err != nil || len(msgs) != 1 || msgs[0].ID != id2 {
		t.Fatalf("post-restart sync = %v %v", msgs, err)
	}
}

// TestGroupAndReplyChain proves a 3-party conversation delivers to
// both recipients with the full participant set, and NIP-10 reply
// markers survive the round trip.
func TestGroupAndReplyChain(t *testing.T) {
	w := newWorld(t)
	a, b, c := w.transport("alice"), w.transport("bob"), w.transport("carol")
	conv := a.NewConversation([]string{w.pub("bob"), w.pub("carol")}, "group")
	rootID, _, err := a.Send(ctx(), conv, transport.Outgoing{Content: "root msg"}, "g-1")
	if err != nil {
		t.Fatal(err)
	}
	replyID, _, err := b.Send(ctx(), conv,
		transport.Outgoing{Content: "reply msg", ReplyTo: rootID, Root: rootID}, "g-2")
	if err != nil {
		t.Fatal(err)
	}
	_ = replyID
	for _, tr := range []*nostrtransport.Transport{b, c} {
		msgs, _, err := tr.Sync(ctx(), nil)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]transport.Message{}
		for _, m := range msgs {
			seen[m.Content] = m
		}
		root, ok := seen["root msg"]
		if !ok || len(root.Participants) != 3 {
			t.Fatalf("root delivery = %+v", seen)
		}
	}
	msgs, _, _ := c.Sync(ctx(), nil)
	_ = msgs
	c2msgs, _, err := w.transport("carol").Sync(ctx(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = c2msgs
	// Alice sees bob's reply with markers intact.
	amsgs, _, err := a.Sync(ctx(), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range amsgs {
		if m.Content == "reply msg" {
			found = true
			if m.ReplyTo != rootID || m.Root != rootID || m.Sender != w.pub("bob") {
				t.Fatalf("reply markers = %+v", m)
			}
		}
	}
	if !found {
		t.Fatal("alice never received the group reply")
	}
}

// TestMediaAndPrivateFile proves Blossom put/get with hash
// verification, corrupted downloads refused, and a kind 15 private
// file round-trip (wrong decryption key refused).
func TestMediaAndPrivateFile(t *testing.T) {
	w := newWorld(t)
	a, b := w.transport("alice"), w.transport("bob")
	hash, err := a.PutMedia(ctx(), []byte("blob contents"))
	if err != nil || len(hash) != 64 {
		t.Fatalf("PutMedia = %q %v", hash, err)
	}
	data, err := b.GetMedia(ctx(), hash)
	if err != nil || string(data) != "blob contents" {
		t.Fatalf("GetMedia = %q %v", data, err)
	}
	w.blossom.CorruptOnGet = true
	if _, err := b.GetMedia(ctx(), hash); err == nil {
		t.Fatal("corrupted blob accepted")
	}
	w.blossom.CorruptOnGet = false

	conv := a.NewConversation([]string{w.pub("bob")}, "")
	if _, ack, err := a.SendFile(ctx(), conv, "text/plain", []byte("secret file body"), "f-1"); err != nil || ack != transport.AckOK {
		t.Fatalf("SendFile = %v %v", ack, err)
	}
	msgs, _, err := b.Sync(ctx(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var fileMsg *transport.Message
	for i := range msgs {
		if msgs[i].File != nil {
			fileMsg = &msgs[i]
		}
	}
	if fileMsg == nil {
		t.Fatalf("no file message in %v", msgs)
	}
	plain, err := b.FetchFile(ctx(), *fileMsg)
	if err != nil || string(plain) != "secret file body" {
		t.Fatalf("FetchFile = %q %v", plain, err)
	}
	bad := *fileMsg
	badFile := *fileMsg.File
	badFile.DecryptionKey = strings.Repeat("00", 32)
	bad.File = &badFile
	if _, err := b.FetchFile(ctx(), bad); err == nil {
		t.Fatal("wrong decryption key accepted")
	}
}

// TestDeletionRequest proves Redact publishes a kind 5 and the
// sender's own view no longer surfaces the message.
func TestDeletionRequest(t *testing.T) {
	w := newWorld(t)
	a := w.transport("alice")
	conv := a.NewConversation([]string{w.pub("bob")}, "")
	id, _, err := a.Send(ctx(), conv, transport.Outgoing{Content: "take this back"}, "d-1")
	if err != nil {
		t.Fatal(err)
	}
	if msgs, _, _ := a.Sync(ctx(), nil); len(msgs) == 0 {
		t.Fatal("self-copy never synced before redact (neighbour missing)")
	}
	if err := a.Redact(ctx(), id); err != nil {
		t.Fatal(err)
	}
	found5 := false
	for _, ev := range w.relay.Events() {
		if ev.Kind == nostr.KindDelete && ev.PubKey == w.pub("alice") {
			found5 = true
		}
	}
	if !found5 {
		t.Fatal("no kind 5 deletion event at the relay")
	}
	// Fresh state view: tombstone in persisted cursor filters it.
	if msgs, _, _ := a.Sync(ctx(), nil); len(msgs) != 0 {
		t.Fatalf("redacted message resurfaced: %v", msgs)
	}
}

// TestOversizeAndFutureRefused proves oversize sends are refused
// pre-publish beside a valid neighbour, and far-future wraps never
// surface on Sync.
func TestOversizeAndFutureRefused(t *testing.T) {
	w := newWorld(t)
	a, b := w.transport("alice"), w.transport("bob")
	conv := a.NewConversation([]string{w.pub("bob")}, "")
	if _, _, err := a.Send(ctx(), conv,
		transport.Outgoing{Content: strings.Repeat("x", 70000)}, "big-1"); err == nil {
		t.Fatal("oversize send accepted")
	}
	if _, ack, err := a.Send(ctx(), conv, transport.Outgoing{Content: "small ok"}, "small-1"); err != nil || ack != transport.AckOK {
		t.Fatalf("valid neighbour after oversize = %v %v", ack, err)
	}
	parts := []string{w.pub("alice"), w.pub("bob")}
	publishRaw(t, w, craftWrap(t,
		rumorFrom(w.keys["alice"], parts, "from the future", time.Now().Unix()+7200),
		w.keys["alice"], w.pub("bob"), false))
	msgs, _, err := b.Sync(ctx(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.Content == "from the future" {
			t.Fatal("far-future message delivered")
		}
	}
	found := false
	for _, m := range msgs {
		if m.Content == "small ok" {
			found = true
		}
	}
	if !found {
		t.Fatal("valid neighbour lost beside future refusal")
	}
}

// TestAuthRequiredRelay proves NIP-42: without an auth key the
// relay refuses publishes; the transport (with its identity key)
// authenticates and works.
func TestAuthRequiredRelay(t *testing.T) {
	w := newWorldOpts(t, testrelay.Options{RequireAuth: true})
	// Raw client without AUTH key: publish refused.
	ev := rumorFrom(w.keys["alice"], []string{w.pub("bob")}, "no auth", time.Now().Unix())
	wrap := craftWrap(t, ev, w.keys["alice"], w.pub("bob"), false)
	raw := &relay.Client{URL: w.relay.URL}
	if err := raw.Dial(ctx()); err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	res, err := raw.Publish(ctx(), wrap)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stored() {
		t.Fatalf("unauthenticated publish stored: %+v", res)
	}
	// Transport authenticates with its identity key.
	a, b := w.transport("alice"), w.transport("bob")
	conv := a.NewConversation([]string{w.pub("bob")}, "")
	id, ack, err := a.Send(ctx(), conv, transport.Outgoing{Content: "authed hello"}, "auth-1")
	if err != nil || ack != transport.AckOK {
		t.Fatalf("authed send = %v %v", ack, err)
	}
	msgs, _, err := b.Sync(ctx(), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range msgs {
		if m.ID == id {
			found = true
		}
	}
	if !found {
		t.Fatalf("authed message not synced: %v", msgs)
	}
}

// TestCursorWindowGap documents the bounded-window contract: a
// wrap older than (cursor since - skew) is outside the query
// window and is not delivered, while in-window traffic flows.
func TestCursorWindowGap(t *testing.T) {
	w := newWorld(t)
	a, b := w.transport("alice"), w.transport("bob")
	conv := a.NewConversation([]string{w.pub("bob")}, "")
	if _, _, err := a.Send(ctx(), conv, transport.Outgoing{Content: "fresh"}, "w-1"); err != nil {
		t.Fatal(err)
	}
	_, cur, err := b.Sync(ctx(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Ancient wrap: crafted with wrap time far outside the window.
	parts := []string{w.pub("alice"), w.pub("bob")}
	old := rumorFrom(w.keys["alice"], parts, "ancient", time.Now().Unix()-30*24*3600)
	seal, err := nostr.SealRumor(w.keys["alice"], old, w.pub("bob"), time.Now().Unix()-30*24*3600)
	if err != nil {
		t.Fatal(err)
	}
	// SealRumor jitters at most 2 days back from its input time, so
	// the wrap is ancient too.
	wrap, err := nostr.WrapSeal(seal, w.pub("bob"), time.Now().Unix()-30*24*3600)
	if err != nil {
		t.Fatal(err)
	}
	publishRaw(t, w, wrap)
	msgs, _, err := b.Sync(ctx(), cur)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.Content == "ancient" {
			t.Fatal("out-of-window message delivered despite cursor window")
		}
	}
	if _, _, err := a.Send(ctx(), conv, transport.Outgoing{Content: "still fresh"}, "w-2"); err != nil {
		t.Fatal(err)
	}
	msgs, _, err = b.Sync(ctx(), cur)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range msgs {
		if m.Content == "still fresh" {
			found = true
		}
	}
	if !found {
		t.Fatal("in-window neighbour lost")
	}
}

// TestSameRumorTwoWrapsDedup proves rumor-level dedup: the same
// sealed rumor delivered under two different gift wraps (anyone
// holding the seal blob can re-wrap it) surfaces exactly once.
func TestSameRumorTwoWrapsDedup(t *testing.T) {
	w := newWorld(t)
	b := w.transport("bob")
	parts := []string{w.pub("alice"), w.pub("bob")}
	rumor := rumorFrom(w.keys["alice"], parts, "one rumor two wraps", time.Now().Unix())
	seal, err := nostr.SealRumor(w.keys["alice"], rumor, w.pub("bob"), time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		wrap, err := nostr.WrapSeal(seal, w.pub("bob"), time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		publishRaw(t, w, wrap)
	}
	msgs, _, err := b.Sync(ctx(), nil)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, m := range msgs {
		if m.ID == rumor.ID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("rumor surfaced %d times under two wraps", count)
	}
}

// The tests below pin the RN1-01 revision: an unverified or
// far-future wrap must never advance the sync cursor or enter the
// seen sets, routing must pin the relay-list author, file sends
// conflict on different data, concurrent sends coalesce, and
// cursor persistence failures must surface.

// TestPoisonedWrapDoesNotBlindSync proves the N1 fix: one junk
// kind-1059 wrap with created_at a decade ahead, p-tagged to the
// victim and signed by a stranger, neither delivers, nor advances
// the cursor, nor blinds later legitimate traffic — before or
// after a restart from the persisted state.
func TestPoisonedWrapDoesNotBlindSync(t *testing.T) {
	w := newWorld(t)
	a, b := w.transport("alice"), w.transport("bob")
	conv := a.NewConversation([]string{w.pub("bob")}, "")

	poison := &nostr.Event{
		CreatedAt: time.Now().Unix() + 10*365*24*3600,
		Kind:      nostr.KindGiftWrap,
		Tags:      [][]string{{"p", w.pub("bob")}},
		Content:   "not even ciphertext",
	}
	if err := w.keys["mallory"].SignEvent(poison); err != nil {
		t.Fatal(err)
	}
	publishRaw(t, w, poison)

	if msgs, _, err := b.Sync(ctx(), nil); err != nil || len(msgs) != 0 {
		t.Fatalf("poison sync = %v msgs, err %v; want 0/nil", msgs, err)
	}
	id, ack, err := a.Send(ctx(), conv, transport.Outgoing{Content: "after poison"}, "p-1")
	if err != nil || ack != transport.AckOK {
		t.Fatalf("legit send after poison = %v %v", ack, err)
	}
	msgs, _, err := b.Sync(ctx(), nil)
	if err != nil || len(msgs) != 1 || msgs[0].ID != id {
		t.Fatalf("legit traffic blinded by poison: %v %v", msgs, err)
	}

	b.Close()
	b2 := w.transport("bob") // persisted cursor must not be poisoned
	if msgs, _, err := b2.Sync(ctx(), nil); err != nil || len(msgs) != 0 {
		t.Fatalf("restart redelivered or errored: %v %v", msgs, err)
	}
	id2, _, err := a.Send(ctx(), conv, transport.Outgoing{Content: "after restart"}, "p-2")
	if err != nil {
		t.Fatal(err)
	}
	msgs, _, err = b2.Sync(ctx(), nil)
	if err != nil || len(msgs) != 1 || msgs[0].ID != id2 {
		t.Fatalf("traffic after restart blinded: %v %v", msgs, err)
	}
}

// TestSkewedLegitWrapEventuallyDelivers proves a legitimate wrap
// from a clock-skewed sender is held aside — not delivered, not
// counted, not cursor-advancing — while normal traffic flows, and
// delivers once local time catches up into the acceptance window.
func TestSkewedLegitWrapEventuallyDelivers(t *testing.T) {
	w := newWorld(t)
	base := time.Now().Unix()
	var bobNow atomic.Int64
	bobNow.Store(base)
	mk := func(name string, nowFn func() time.Time) *nostrtransport.Transport {
		tr, err := nostrtransport.New(nostrtransport.Config{
			Key: w.keys[name], StateDir: w.dirs[name],
			ReadRelays: []string{w.relay.URL}, WriteRelays: []string{w.relay.URL},
			BlossomServers: []string{w.blossom.URL}, Now: nowFn,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { tr.Close() })
		return tr
	}
	skewed := mk("alice", func() time.Time { return time.Unix(base+3600, 0) })
	b := mk("bob", func() time.Time { return time.Unix(bobNow.Load(), 0) })
	c := w.transport("carol")

	conv := skewed.NewConversation([]string{w.pub("bob")}, "")
	if _, ack, err := skewed.Send(ctx(), conv,
		transport.Outgoing{Content: "from one hour ahead"}, "sk-1"); err != nil || ack != transport.AckOK {
		t.Fatalf("skewed send = %v %v", ack, err)
	}
	if _, _, err := c.Send(ctx(), c.NewConversation([]string{w.pub("bob")}, ""),
		transport.Outgoing{Content: "right on time"}, "sk-2"); err != nil {
		t.Fatal(err)
	}
	msgs, _, err := b.Sync(ctx(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var contents []string
	for _, m := range msgs {
		contents = append(contents, m.Content)
	}
	if len(contents) != 1 || contents[0] != "right on time" {
		t.Fatalf("before catch-up delivered %v, want only the on-time neighbour", contents)
	}

	bobNow.Store(base + 3600 + 60)
	msgs, _, err = b.Sync(ctx(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].Content != "from one hour ahead" ||
		msgs[0].Sender != w.pub("alice") {
		t.Fatalf("skewed wrap lost after catch-up: %v", msgs)
	}
	if msgs, _, err := b.Sync(ctx(), nil); err != nil || len(msgs) != 0 {
		t.Fatalf("skewed wrap redelivered: %v %v", msgs, err)
	}
}

// TestResolveIgnoresForeignRelayList proves N2: when a relay
// answers the authors query with a stranger's kind 10050 pointing
// at a dead relay, routing ignores it (author pinned to the
// queried pubkey) and the send still lands via the fallback.
func TestResolveIgnoresForeignRelayList(t *testing.T) {
	w := newWorldOpts(t, testrelay.Options{LooseAuthors: true})
	dead, err := nostr.BuildDMRelaysEvent(w.keys["mallory"],
		[]string{"ws://127.0.0.1:1"}, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	publishRaw(t, w, dead)

	a, b := w.transport("alice"), w.transport("bob")
	conv := a.NewConversation([]string{w.pub("bob")}, "")
	id, ack, err := a.Send(ctx(), conv, transport.Outgoing{Content: "not redirected"}, "r-1")
	if err != nil || ack != transport.AckOK {
		t.Fatalf("send redirected by foreign relay list: ack %v err %v", ack, err)
	}
	msgs, _, err := b.Sync(ctx(), nil)
	if err != nil || len(msgs) != 1 || msgs[0].ID != id {
		t.Fatalf("message lost under foreign relay list: %v %v", msgs, err)
	}
}

// TestSendFileIdempotencyConflict proves N3: the same idempotency
// key with different file data refuses, while a same-data retry
// replays the stored message without new relay traffic.
func TestSendFileIdempotencyConflict(t *testing.T) {
	w := newWorld(t)
	a := w.transport("alice")
	conv := a.NewConversation([]string{w.pub("bob")}, "")
	id1, ack, err := a.SendFile(ctx(), conv, "text/plain", []byte("version one"), "f-key")
	if err != nil || ack != transport.AckOK {
		t.Fatalf("first SendFile = %v %v", ack, err)
	}
	if _, _, err := a.SendFile(ctx(), conv, "text/plain", []byte("version TWO"), "f-key"); !errors.Is(err, nostrtransport.ErrIdempotencyConflict) {
		t.Fatalf("different data under same key = %v, want ErrIdempotencyConflict", err)
	}
	before := len(w.relay.Events())
	id2, ack, err := a.SendFile(ctx(), conv, "text/plain", []byte("version one"), "f-key")
	if err != nil || ack != transport.AckOK || id2 != id1 {
		t.Fatalf("same-data retry = %q %v %v, want stored id ACK", id2, ack, err)
	}
	if got := len(w.relay.Events()); got != before {
		t.Fatalf("retry stored new events: %d -> %d", before, got)
	}
}

// TestConcurrentSendSameKeyCoalesced proves N4: concurrent Send
// calls with one idempotency key run one owner — every caller
// gets the same id/ACK and exactly one wrap per recipient exists;
// concurrent different content under the key yields one winner
// and a conflict for the loser.
func TestConcurrentSendSameKeyCoalesced(t *testing.T) {
	w := newWorld(t)
	a, b := w.transport("alice"), w.transport("bob")
	conv := a.NewConversation([]string{w.pub("bob")}, "")

	const n = 8
	ids := make([]string, n)
	acks := make([]transport.AckStatus, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ids[i], acks[i], errs[i] = a.Send(ctx(), conv,
				transport.Outgoing{Content: "exactly once"}, "conc-1")
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil || acks[i] != transport.AckOK || ids[i] == "" || ids[i] != ids[0] {
			t.Fatalf("caller %d = id %q ack %v err %v (id0 %q)", i, ids[i], acks[i], errs[i], ids[0])
		}
	}
	wraps := 0
	for _, ev := range w.relay.Events() {
		if ev.Kind == nostr.KindGiftWrap {
			wraps++
		}
	}
	if wraps != 2 { // bob + alice self-copy
		t.Fatalf("relay holds %d wraps, want 2 (one per recipient)", wraps)
	}
	msgs, _, err := b.Sync(ctx(), nil)
	if err != nil || len(msgs) != 1 || msgs[0].ID != ids[0] {
		t.Fatalf("delivered = %v %v, want exactly the coalesced message", msgs, err)
	}

	var wg2 sync.WaitGroup
	res := make([]error, 2)
	for i, content := range []string{"winner A", "winner B"} {
		wg2.Add(1)
		go func(i int, content string) {
			defer wg2.Done()
			_, _, res[i] = a.Send(ctx(), conv, transport.Outgoing{Content: content}, "conc-2")
		}(i, content)
	}
	wg2.Wait()
	okCount, conflictCount := 0, 0
	for _, err := range res {
		switch {
		case err == nil:
			okCount++
		case errors.Is(err, nostrtransport.ErrIdempotencyConflict):
			conflictCount++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if okCount != 1 || conflictCount != 1 {
		t.Fatalf("different-content race: %d ok, %d conflict; want 1/1", okCount, conflictCount)
	}
}

// TestSyncSurfacesCursorSaveError proves N5: when the cursor
// cannot be persisted, Sync reports the failure instead of
// silently degrading to redelivery-after-restart.
func TestSyncSurfacesCursorSaveError(t *testing.T) {
	w := newWorld(t)
	b := w.transport("bob")
	dir := w.dirs["bob"]
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	if _, _, err := b.Sync(ctx(), nil); err == nil {
		t.Fatal("Sync swallowed the cursor persistence failure")
	}
}
