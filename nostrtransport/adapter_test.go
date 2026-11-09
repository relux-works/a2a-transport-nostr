package nostrtransport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	seam "relux.works/a2a-transport-nostr/internal/seamprovisional"
	"relux.works/a2a-transport-nostr/internal/seamprovisional/conformancetest"
	"relux.works/a2a-transport-nostr/nostr"
	"relux.works/a2a-transport-nostr/relay"
	"relux.works/a2a-transport-nostr/testblossom"
	"relux.works/a2a-transport-nostr/testrelay"
)

type seamWorld struct {
	a, b, c        *Adapter
	r              *testrelay.Relay
	blob           *testblossom.Server
	conv           ConversationID
	configs        []SeamConfig
	root, sentinel string
}

func newSeamWorld(t *testing.T) *seamWorld {
	t.Helper()
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	r, e := testrelay.StartWithOptions(testrelay.Options{TrueDuplicate: true})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(r.Close)
	blob, e := testblossom.Start()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(blob.Close)
	urls, _ := json.Marshal([]string{r.URL})
	blobs, _ := json.Marshal([]string{blob.URL})
	w := &seamWorld{r: r, blob: blob, root: root, sentinel: filepath.Join(root, "sentinel")}
	if e := os.WriteFile(w.sentinel, []byte("untouched"), 0600); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3; i++ {
		cfg := SeamConfig{StateDir: filepath.Join(root, fmt.Sprint(i)), Settings: map[string]string{"read_relays": string(urls), "blossom_servers": string(blobs)}}
		a, e := Open(cfg)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { a.Close() })
		w.configs = append(w.configs, cfg)
		switch i {
		case 0:
			w.a = a
		case 1:
			w.b = a
		case 2:
			w.c = a
		}
	}
	adapters := []*Adapter{w.a, w.b, w.c}
	sort.Slice(adapters, func(i, j int) bool { return adapters[i].core.Identity() < adapters[j].core.Identity() })
	oldConfigs := w.configs
	w.configs = nil
	for _, a := range adapters {
		for _, cfg := range oldConfigs {
			if cfg.StateDir == a.dir {
				w.configs = append(w.configs, cfg)
			}
		}
	}
	w.a, w.b, w.c = adapters[0], adapters[1], adapters[2]
	w.conv, e = w.a.ConversationFor([]PrincipalID{PrincipalID(w.b.core.Identity()), PrincipalID(w.c.core.Identity())}, "")
	if e != nil {
		t.Fatal(e)
	}
	return w
}
func (w *seamWorld) restartB(t *testing.T) *Adapter {
	t.Helper()
	w.b.Close()
	var e error
	w.b, e = Open(w.configs[1])
	if e != nil {
		t.Fatal(e)
	}
	a := w.b
	t.Cleanup(func() { a.Close() })
	return a
}
func (w *seamWorld) inject(t *testing.T, kind string) EventID {
	t.Helper()
	c, _ := w.a.conversation(w.conv)
	body, _ := json.Marshal(wireMessage{Version: 1, Text: "injected"})
	at := time.Now().Unix()
	rumor, e := nostr.BuildRumor(w.a.core.cfg.Key, c.P, nostr.KindRumor, string(body), nostr.RumorOptions{}, at)
	if e != nil {
		t.Fatal(e)
	}
	if kind == "unverifiable-sender" {
		rumor.PubKey = w.c.core.Identity()
		rumor.ID = rumor.ComputeID()
	}
	if kind == "backdated-publish" {
		rumor.CreatedAt = at - 47*3600
		rumor.ID = rumor.ComputeID()
	}
	seal, e := nostr.SealRumor(w.a.core.cfg.Key, rumor, w.b.core.Identity(), at)
	if e != nil {
		t.Fatal(e)
	}
	wrap, e := nostr.WrapSeal(seal, w.b.core.Identity(), at)
	if e != nil {
		t.Fatal(e)
	}
	if kind == "backdated-publish" {
		key, _ := nostr.GeneratePrivKey()
		wrap.CreatedAt = at - 47*3600
		// The wrap encryption key must match its new signer: recreate encrypted seal.
		ck, _ := nostr.ConversationKey(key, w.b.core.Identity())
		raw, _ := json.Marshal(seal)
		wrap.Content, e = nostr.EncryptNIP44(string(raw), ck, [32]byte{})
		if e != nil {
			t.Fatal(e)
		}
		if e = key.SignEvent(wrap); e != nil {
			t.Fatal(e)
		}
	}
	client := &relay.Client{URL: w.r.URL}
	defer client.Close()
	if r, e := client.Publish(context.Background(), wrap); e != nil || !r.Accepted {
		t.Fatal("injection failed", e)
	}
	return EventID(rumor.ID)
}

// These groups exercise the real adapter through local relay/Blossom servers;
// the provisional runner is not represented as the eventual upstream suite.
func TestProvisionalConformance(t *testing.T) {
	conformancetest.Run(t, conformancetest.Harness{New: func(t *testing.T) *conformancetest.World {
		w := newSeamWorld(t)
		var cw *conformancetest.World
		var logs bytes.Buffer
		oldLog := log.Writer()
		log.SetOutput(&logs)
		t.Cleanup(func() { log.SetOutput(oldLog) })
		cw = &conformancetest.World{A: w.a, B: w.b, Conversation: w.conv, Advance: func(d time.Duration) { at := w.a.now().Add(d); w.a.now = func() time.Time { return at } }, Fault: func(name string) func() {
			switch name {
			case "fail-after-submit":
				w.r.SetRecipientMode(w.b.core.Identity(), "after-submit")
				return func() { w.r.SetRecipientMode(w.b.core.Identity(), "") }
			case "partial-ack":
				w.r.SetRecipientMode(w.c.core.Identity(), "silent")
				return func() { w.r.SetRecipientMode(w.c.core.Identity(), "") }
			case "drop-key-on-retry":
				original := cw.A
				cw.A = &droppedKeyTransport{SeamTransport: original}
				return func() { cw.A = original }
			case "oversize":
				original := cw.Oversize
				cw.Oversize = Message{Text: strings.Repeat("x", w.a.Caps().MaxContentBytes+1)}
				return func() { cw.Oversize = original }
			case "foreign-cursor":
				original := cw.Foreign
				b, e := w.b.Sync(context.Background(), nil, SyncOptions{})
				if e != nil {
					t.Fatal(e)
				}
				cw.Foreign = b.Next
				return func() { cw.Foreign = original }
			default:
				t.Fatalf("harness missing fault hook %s", name)
				return nil
			}
		}, Inject: func(kind string) EventID { return w.inject(t, kind) }, Restart: func() SeamTransport { return w.restartB(t) }, Calls: w.r.Calls, Dropped: func() uint64 { return w.b.Dropped() }, Logs: func() string { return logs.String() }, StateDirs: []string{w.a.dir, w.b.dir, w.c.dir}, Sentinel: w.sentinel}
		if os.Getenv("N2_CONFORMANCE_PLANT") == "drop-key" {
			cw.Fault("drop-key-on-retry")
		}
		return cw
	}})
}
func mustSend(t *testing.T, w *seamWorld, key, text string) SendResult {
	t.Helper()
	r, e := w.a.Send(context.Background(), SendRequest{Conversation: w.conv, Message: Message{Text: text}, IdempotencyKey: key})
	if e != nil || r.Outcome != ACK {
		t.Fatalf("send: outcome %s error %v", r.Outcome, e)
	}
	return r
}

// A restart reuses every original seal/wrap and skips parties already ACKed.
func TestSeamPartialRestart(t *testing.T) {
	w := newSeamWorld(t)
	w.r.SetRecipientMode(w.c.core.Identity(), "silent")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	r, e := w.a.Send(ctx, SendRequest{Conversation: w.conv, Message: Message{Text: "partial"}, IdempotencyKey: "partial"})
	cancel()
	if e != nil || r.Outcome != UNKNOWN {
		t.Fatal("partial delivery falsely ACKed")
	}
	raw, e := readPrivate(filepath.Join(w.a.dir, "seam-send", sendFileName("partial")), 2<<20)
	if e != nil {
		t.Fatal(e)
	}
	var before seamSend
	json.Unmarshal(raw, &before)
	counts := map[string]int{}
	for _, p := range before.Parts {
		counts[p.Wrap.ID] = w.r.Attempts(p.Wrap.ID)
	}
	w.a.Close()
	w.a, e = Open(w.configs[0])
	if e != nil {
		t.Fatal(e)
	}
	a := w.a
	t.Cleanup(func() { a.Close() })
	w.r.SetRecipientMode(w.c.core.Identity(), "")
	two := mustSend(t, w, "partial", "partial")
	if r.Event != two.Event {
		t.Fatal("restart changed rumor")
	}
	after, _ := readPrivate(filepath.Join(w.a.dir, "seam-send", sendFileName("partial")), 2<<20)
	var rec seamSend
	json.Unmarshal(after, &rec)
	for p, part := range before.Parts {
		x, _ := json.Marshal(part.Wrap)
		y, _ := json.Marshal(rec.Parts[p].Wrap)
		if !bytes.Equal(x, y) {
			t.Fatal("retry changed wrap")
		}
		if part.Ack && w.r.Attempts(part.Wrap.ID) != counts[part.Wrap.ID] {
			t.Fatal("ACKed party republished")
		}
	}
	for _, receiver := range []*Adapter{w.a, w.b, w.c} {
		b, e := receiver.Sync(context.Background(), nil, SyncOptions{})
		if e != nil || len(b.Events) != 1 || b.Events[0].ID != r.Event {
			t.Fatal("party missing or duplicate")
		}
	}
}

// Definite original refusal differs from lost ACK, false duplicate and timeout.
func TestSeamRefusalTable(t *testing.T) {
	for _, mode := range []string{"reject", "after-submit", "silent", "false-duplicate"} {
		t.Run(mode, func(t *testing.T) {
			w := newSeamWorld(t)
			if mode == "false-duplicate" {
				w.r.SetRecipientMode(w.b.core.Identity(), "after-submit")
			} else {
				w.r.SetRecipientMode(w.b.core.Identity(), mode)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			r, e := w.a.Send(ctx, SendRequest{Conversation: w.conv, Message: Message{Text: "x"}, IdempotencyKey: "same"})
			cancel()
			if e != nil {
				t.Fatal(e)
			}
			want := UNKNOWN
			if mode == "reject" {
				want = REFUSED
			}
			if r.Outcome != want {
				t.Fatalf("want %s got %s", want, r.Outcome)
			}
			if mode == "false-duplicate" {
				w.r.SetRecipientMode(w.b.core.Identity(), mode)
				r, e = w.a.Send(context.Background(), SendRequest{Conversation: w.conv, Message: Message{Text: "x"}, IdempotencyKey: "same"})
				if e != nil || r.Outcome != UNKNOWN {
					t.Fatal("false duplicate acknowledged")
				}
			}
			if mode == "after-submit" {
				w.r.SetRecipientMode(w.b.core.Identity(), "reject")
				r, e = w.a.Send(context.Background(), SendRequest{Conversation: w.conv, Message: Message{Text: "x"}, IdempotencyKey: "same"})
				if e != nil || r.Outcome != UNKNOWN {
					t.Fatal("uncertain earlier send turned into definite refusal")
				}
			}
		})
	}
}

// Changed content conflicts before I/O; locks/modes/key identity fail closed.
func TestSeamStateAndConflict(t *testing.T) {
	w := newSeamWorld(t)
	mustSend(t, w, "key", "original")
	calls := w.r.Calls()
	_, e := w.a.Send(context.Background(), SendRequest{Conversation: w.conv, Message: Message{Text: "other"}, IdempotencyKey: "key"})
	if seam.Code(e) != "invalid_reference" || w.r.Calls() != calls {
		t.Fatal("conflict reached wire")
	}
	if other, e := Open(w.configs[0]); e == nil {
		other.Close()
		t.Fatal("double owner admitted")
	}
	w.a.Close()
	if e := os.Chmod(filepath.Join(w.a.dir, "identity.key"), 0644); e != nil {
		t.Fatal(e)
	}
	if other, e := Open(w.configs[0]); e == nil {
		other.Close()
		t.Fatal("public keyfile admitted")
	}
}

// Exact content boundary includes JSON-escape worst cases through both NIP44 layers.
func TestSeamEscapedBoundAndMetadata(t *testing.T) {
	w := newSeamWorld(t)
	for i, text := range []string{strings.Repeat("x", seamMaxContent), strings.Repeat("\x00", seamMaxContent), strings.Repeat("\\", seamMaxContent)} {
		mustSend(t, w, fmt.Sprint(i), text)
	}
	n := w.r.Calls()
	_, e := w.a.Send(context.Background(), SendRequest{Conversation: w.conv, Message: Message{Text: strings.Repeat("x", seamMaxContent+1)}, IdempotencyKey: "over"})
	if seam.Code(e) != "content_too_large" || w.r.Calls() != n {
		t.Fatal("bound+1 submitted")
	}
}

// Kind15 metadata remains sealed; hashes/limits authenticate before writer effects.
func TestSeamPrivateFile(t *testing.T) {
	w := newSeamWorld(t)
	ref, e := w.a.Upload(context.Background(), strings.NewReader("secret"), MediaMeta{Size: 6, ContentType: "text/plain"})
	if e != nil {
		t.Fatal(e)
	}
	r, e := w.a.Send(context.Background(), SendRequest{Conversation: w.conv, Message: Message{Text: "file", Attachments: []MediaRef{ref}}, IdempotencyKey: "file"})
	if e != nil || r.Outcome != ACK {
		t.Fatal("kind15 send failed", e)
	}
	b, e := w.b.Sync(context.Background(), nil, SyncOptions{})
	if e != nil || len(b.Events) != 1 || len(b.Events[0].Message.Attachments) != 1 {
		t.Fatal("file message missing")
	}
	var out bytes.Buffer
	_, e = w.b.Download(context.Background(), b.Events[0].Message.Attachments[0], &out, 6)
	if e != nil || out.String() != "secret" {
		t.Fatal("file roundtrip failed", e)
	}
	out.Reset()
	_, e = w.b.Download(context.Background(), ref, &out, 5)
	if seam.Code(e) != "content_too_large" || out.Len() != 0 {
		t.Fatal("limit did not preserve output")
	}
}

// Every nonempty malformed/foreign cursor fails before wire I/O; valid cursors
// retain identity and declared gap reasons through time and relay-set changes.
func TestSeamCursorGapsAndBounds(t *testing.T) {
	w := newSeamWorld(t)
	b, e := w.b.Sync(context.Background(), nil, SyncOptions{})
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range []Cursor{Cursor(`{}`), Cursor(`null`), Cursor(`{"v":2}`), append(append(Cursor{}, b.Next...), []byte(` {}`)...)} {
		n := w.r.Calls()
		if _, e := w.b.Sync(context.Background(), bad, SyncOptions{}); seam.Code(e) != "invalid_cursor" || n != w.r.Calls() {
			t.Fatal("invalid cursor reset or reached wire")
		}
	}
	oldNow := w.b.now
	w.b.now = func() time.Time { return time.Now().Add(50 * time.Hour) }
	expired, e := w.b.Sync(context.Background(), b.Next, SyncOptions{})
	if e != nil || !hasGap(expired, "window_exceeded") {
		t.Fatal("elapsed window not declared")
	}
	w.b.now = oldNow
	another, e := testrelay.Start()
	if e != nil {
		t.Fatal(e)
	}
	defer another.Close()
	w.b.core.cfg.ReadRelays = append(w.b.core.cfg.ReadRelays, another.URL)
	changed, e := w.b.Sync(context.Background(), b.Next, SyncOptions{})
	if e != nil || !hasGap(changed, "relay_set_changed") {
		t.Fatal("relay-set change not declared")
	}
	another.Close()
	down, e := w.b.Sync(context.Background(), changed.Next, SyncOptions{})
	if e != nil || !hasGap(down, "relay_unreachable") {
		t.Fatal("relay outage not declared")
	}
	w.b.core.cfg.ReadRelays = []string{w.r.URL}
	mustSend(t, w, "one", "one")
	mustSend(t, w, "two", "two")
	limited, e := w.b.Sync(context.Background(), nil, SyncOptions{Limit: 1})
	if e != nil || len(limited.Events) != 1 || !hasGap(limited, "timeline_limited") {
		t.Fatal("bounded batch failed")
	}
	next, e := w.b.Sync(context.Background(), limited.Next, SyncOptions{Limit: 1})
	if e != nil || len(next.Events) != 1 || next.Events[0].ID == limited.Events[0].ID {
		t.Fatal("bounded resume lost/duplicated event")
	}
}
func hasGap(b Batch, reason string) bool {
	for _, g := range b.Gaps {
		if g.Reason == reason {
			return true
		}
	}
	return false
}

// The authenticated seal, never the ephemeral wrapper, determines Sender.
func TestSeamSenderIsSeal(t *testing.T) {
	w := newSeamWorld(t)
	id := mustSend(t, w, "sender", "sender").Event
	b, e := w.b.Sync(context.Background(), nil, SyncOptions{})
	if e != nil || len(b.Events) != 1 || b.Events[0].ID != id || b.Events[0].Sender != PrincipalID(w.a.core.Identity()) {
		t.Fatal("sender is not authenticated seal signer")
	}
	for _, ev := range w.r.Events() {
		p, _ := ev.TagFirst("p")
		if ev.Kind == nostr.KindGiftWrap && p == w.b.core.Identity() && string(b.Events[0].Sender) == ev.PubKey {
			t.Fatal("wrap key accepted as sender")
		}
	}
}

// Invalid media is redacted on every formatting path and never reaches network
// or modifies the destination; a valid neighbor still decrypts successfully.
func TestSeamMediaMarker(t *testing.T) {
	w := newSeamWorld(t)
	marker := "N2-PRIVATE-MEDIA-MARKER"
	ref := mediaRef([]byte(marker))
	var out bytes.Buffer
	n := w.r.Calls()
	_, e := w.b.Download(context.Background(), ref, &out, 1024)
	if e == nil || out.Len() != 0 || w.r.Calls() != n {
		t.Fatal("invalid media not refused cleanly")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		if strings.Contains(fmt.Sprintf(format, ref), marker) {
			t.Fatal("MediaRef marker exposed")
		}
	}
	if strings.Contains(fmt.Sprint(e), marker) {
		t.Fatal("MediaRef marker exposed in error")
	}
	valid, e := w.a.Upload(context.Background(), strings.NewReader("valid"), MediaMeta{Size: 5})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.b.Download(context.Background(), valid, &out, 5); e != nil || out.String() != "valid" {
		t.Fatal("valid media neighbor refused")
	}
}

// Losing a key from an initialized root never generates a replacement identity.
func TestSeamMissingKeyRefusesUnchanged(t *testing.T) {
	w := newSeamWorld(t)
	w.a.Close()
	p := filepath.Join(w.a.dir, "identity.key")
	raw, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(p, p+".saved"); e != nil {
		t.Fatal(e)
	}
	if a, e := Open(w.configs[0]); e == nil {
		a.Close()
		t.Fatal("missing key silently replaced")
	}
	if _, e = os.Lstat(p); !os.IsNotExist(e) {
		t.Fatal("replacement key written")
	}
	if e = os.Rename(p+".saved", p); e != nil {
		t.Fatal(e)
	}
	again, e := Open(w.configs[0])
	if e != nil {
		t.Fatal(e)
	}
	defer again.Close()
	after, _ := os.ReadFile(p)
	if !bytes.Equal(raw, after) {
		t.Fatal("key changed")
	}
}

// The drop-key fault hook is a deliberately broken transport wrapper. The real
// provisional runner must reject its retry, specifically at logical identity.
type droppedKeyTransport struct {
	SeamTransport
	serial int
}

func (d *droppedKeyTransport) Send(ctx context.Context, r SendRequest) (SendResult, error) {
	d.serial++
	r.IdempotencyKey += fmt.Sprint("-lost-", d.serial)
	return d.SeamTransport.Send(ctx, r)
}
func TestProvisionalDropKeyHookControl(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestProvisionalConformance/idempotent_retry$", "-test.v")
	cmd.Env = append(os.Environ(), "N2_CONFORMANCE_PLANT=drop-key")
	output, e := cmd.CombinedOutput()
	if e == nil || !bytes.Contains(output, []byte("idempotency key retry changed logical event")) {
		t.Fatal("drop-key hook did not fail intended conformance assertion")
	}
}

// Distinct core transactions are distinct rumors even within one second;
// persisted journal corruption never authorizes a new publish or false ACK.
func TestSeamDistinctTransactionsAndCorruptJournal(t *testing.T) {
	w := newSeamWorld(t)
	at := time.Now()
	w.a.now = func() time.Time { return at }
	one := mustSend(t, w, "one", "same")
	two := mustSend(t, w, "two", "same")
	if one.Event == two.Event {
		t.Fatal("distinct transaction keys collapsed")
	}
	file := filepath.Join(w.a.dir, "seam-send", sendFileName("one"))
	raw, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	var rec seamSend
	if e = json.Unmarshal(raw, &rec); e != nil {
		t.Fatal(e)
	}
	rec.Hash = strings.Repeat("0", 64)
	changed, _ := json.Marshal(rec)
	if e = os.WriteFile(file, changed, 0600); e != nil {
		t.Fatal(e)
	}
	n := w.r.Calls()
	r, e := w.a.Send(context.Background(), SendRequest{Conversation: w.conv, Message: Message{Text: "same"}, IdempotencyKey: "one"})
	if e != nil || r.Outcome != UNKNOWN || n != w.r.Calls() {
		t.Fatal("corrupt journal submitted or falsely resolved")
	}
}

// Received text cannot flow into diagnostics on validation failures.
func TestSeamReceivedTextDiagnostics(t *testing.T) {
	w := newSeamWorld(t)
	marker := "N2-RECEIVED-TEXT-MARKER"
	for _, req := range []SendRequest{{Conversation: ConversationID(marker), Message: Message{Text: marker}, IdempotencyKey: "bad"}, {Conversation: w.conv, Message: Message{Text: marker, Re: EventID(marker)}, IdempotencyKey: "bad"}, {Conversation: w.conv, Message: Message{Text: strings.Repeat(marker, 500)}, IdempotencyKey: "bad"}} {
		n := w.r.Calls()
		_, e := w.a.Send(context.Background(), req)
		if e == nil || strings.Contains(e.Error(), marker) || w.r.Calls() != n {
			t.Fatal("received text leaked or invalid input submitted")
		}
	}
	mustSend(t, w, "neighbor", marker)
}

// A symlink to legacy cursor state is refused without opening or altering it.
func TestSeamLegacyStateRefused(t *testing.T) {
	w := newSeamWorld(t)
	w.a.Close()
	before, e := os.ReadFile(w.sentinel)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(w.sentinel, filepath.Join(w.a.dir, "cursor.json")); e != nil {
		t.Fatal(e)
	}
	if a, e := Open(w.configs[0]); e == nil {
		a.Close()
		t.Fatal("legacy cursor symlink admitted")
	}
	after, _ := os.ReadFile(w.sentinel)
	if !bytes.Equal(before, after) {
		t.Fatal("sibling state touched")
	}
}
