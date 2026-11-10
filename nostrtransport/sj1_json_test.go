package nostrtransport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	seam "github.com/relux-works/a2a-swarm/transport"
	"github.com/relux-works/a2a-transport-nostr/nostr"
	"github.com/relux-works/a2a-transport-nostr/relay"
	legacy "github.com/relux-works/a2a-transport-nostr/transport"
)

func sj1Variants(raw, field, good, bad string) []string {
	key := `"` + field + `":`
	escaped := `"\u` + fmt.Sprintf("%04x", field[0]) + field[1:] + `":`
	return []string{strings.Replace(raw, key+good, key+good+`,`+key+bad, 1), strings.Replace(raw, key+good, key+bad+`,`+key+good, 1), strings.Replace(raw, key+good, key+good+`,`+escaped+bad, 1), strings.Replace(raw, key+good, escaped+good, 1)}
}

// The real signed/encrypted adapter path drops ambiguous envelopes and extension
// maps before caching or adding verified seen IDs. Only drop telemetry/checkpoint
// bookkeeping may change. A valid neighbor still delivers via the same relay.
func TestSJ1InboundEnvelope(t *testing.T) {
	w := newSeamWorld(t)
	c, _ := w.a.conversation(w.conv)
	grant, _ := EncodeGrantPresentation(grantFixture(1))
	ext := `{"` + GrantExtension + `":` + string(grant) + `}`
	valid := `{"v":1,"text":"line\nvalue","extensions":` + ext + `}`
	cases := sj1Variants(valid, "extensions", ext, `[]`)
	for _, value := range sj1Variants(ext, GrantExtension, string(grant), `{"v":9}`) {
		cases = append(cases, strings.Replace(valid, ext, value, 1))
	}
	for _, value := range []string{`{"x":1,"x":2}`, `{"x":2,"x":1}`, `{"x":1,"\u0078":2}`, `{"\u0078":1}`} {
		cases = append(cases, `{"v":1,"text":"line\nvalue","extensions":{"ordinary":`+value+`}}`)
	}
	var badRumors, badWraps []string
	var good string
	for index, body := range append(cases, valid) {
		rumor, e := nostr.BuildRumor(w.a.core.cfg.Key, c.P, nostr.KindRumor, body, nostr.RumorOptions{}, time.Now().Unix())
		if e != nil {
			t.Fatal(e)
		}
		wrap, e := nostr.GiftWrap(rumor, w.a.core.cfg.Key, w.b.core.Identity(), time.Now().Unix())
		if e != nil {
			t.Fatal(e)
		}
		got, e := w.b.verifyWrap(wrap)
		if index < len(cases) {
			if seam.Code(e) != "invalid_reference" || got.ID != "" {
				t.Fatal("SJ1 ambiguous envelope admitted", e)
			}
			badRumors = append(badRumors, rumor.ID)
			badWraps = append(badWraps, wrap.ID)
		} else {
			if e != nil {
				t.Fatal("valid neighbor", e)
			}
			good = rumor.ID
		}
		client := &relay.Client{URL: w.r.URL}
		ack, e := client.Publish(context.Background(), wrap)
		client.Close()
		if e != nil || !ack.Accepted {
			t.Fatal("fixture publish", e)
		}
	}
	batch, e := w.b.Sync(context.Background(), nil, SyncOptions{Initial: true})
	if e != nil || len(batch.Events) != 1 || string(batch.Events[0].ID) != good || batch.Dropped != len(cases) {
		t.Fatal("inbound JSON refusal lost delivery/drop accounting", e)
	}
	cursor, e := w.b.readCursor(batch.Next)
	if e != nil {
		t.Fatal(e)
	}
	for i, id := range badRumors {
		if _, e := os.Stat(filepath.Join(w.b.dir, "seam-events", id+".json")); !os.IsNotExist(e) {
			t.Fatal("refused event cached")
		}
		if _, ok := cursor.Rumors[id]; ok {
			t.Fatal("refused rumor marked seen")
		}
		if _, ok := cursor.Seen[badWraps[i]]; ok {
			t.Fatal("refused wrap marked seen")
		}
	}
}

// Outgoing opaque extension objects are checked before relay calls and send
// journal creation. A legal escaped string value retains ordinary send behavior.
func TestSJ1OutgoingExtensions(t *testing.T) {
	w := newSeamWorld(t)
	before := w.r.Calls()
	for _, raw := range []string{`{"grant":1,"grant":2}`, `{"grant":2,"grant":1}`, `{"grant":1,"gr\u0061nt":2}`, `{"gr\u0061nt":1}`} {
		req := SendRequest{Conversation: w.conv, IdempotencyKey: "sj1-bad", Message: Message{Text: "test", Extensions: map[string]json.RawMessage{"ordinary": json.RawMessage(raw)}}}
		got, e := w.a.Send(context.Background(), req)
		if seam.Code(e) != "invalid_reference" || got.Outcome == ACK {
			t.Fatal("SJ1 ambiguous outgoing extension admitted", e)
		}
		if w.r.Calls() != before {
			t.Fatal("refusal published")
		}
		if _, e := os.Stat(filepath.Join(w.a.dir, "seam-send", sendFileName(req.IdempotencyKey))); !os.IsNotExist(e) {
			t.Fatal("refusal persisted send")
		}
	}
	got, e := w.a.Send(context.Background(), SendRequest{Conversation: w.conv, IdempotencyKey: "sj1-good", Message: Message{Text: "test", Extensions: map[string]json.RawMessage{"ordinary": json.RawMessage(`{"grant":1,"note":"a\nb"}`)}}})
	if e != nil || got.Outcome != ACK {
		t.Fatal("valid send neighbor", e)
	}
}

// Ordinary extension budgeting remains based on serialized bytes: insignificant
// raw JSON whitespace may exceed that budget without changing the wire object.
func TestSJ1ExtensionWhitespaceBudget(t *testing.T) {
	raw := json.RawMessage(`{` + strings.Repeat(" ", maxOrdinaryExtensions+1) + `"value":"a\nb"}`)
	got, e := checkExtensions(map[string]json.RawMessage{"ordinary": raw})
	if e != nil {
		t.Fatal("valid extension whitespace refused", e)
	}
	encoded, e := json.Marshal(got)
	if e != nil || len(encoded) > maxOrdinaryExtensions {
		t.Fatal("serialized extension budget", e)
	}
	if string(got["ordinary"]) != string(raw) {
		t.Fatal("validation rewrote supplied value")
	}
}

// The standalone carrier refuses escaped single keys and both duplicate orders,
// returning no proof bytes; the adjacent valid carrier remains byte-identical.
func TestSJ1CarrierKeys(t *testing.T) {
	raw, _ := EncodeGrantPresentation(grantFixture(1))
	good := `"grant_id":"` + strings.Repeat("a", 64) + `"`
	bad := `"grant_id":"invalid"`
	for _, field := range []string{good + `,` + bad, bad + `,` + good, good + `,"grant_\u0069d":"invalid"`, `"grant_\u0069d":"` + strings.Repeat("a", 64) + `"`} {
		changed := []byte(strings.Replace(string(raw), good, field, 1))
		got, e := DecodeGrantPresentation(changed)
		if seam.Code(e) != "invalid_reference" || len(got.Bytes) != 0 {
			t.Fatal("SJ1 ambiguous carrier admitted", e)
		}
		decoded, e := DecodeGrantPresentation(raw)
		if e != nil || !bytes.Equal(decoded.Bytes, grantFixture(1).Bytes) {
			t.Fatal("valid carrier", e)
		}
	}
}

// Ambiguous durable records refuse retry before relay submission or journal
// replacement. Restoring the original bytes restores the same idempotent ACK.
func TestSJ1DurableRetry(t *testing.T) {
	w := newSeamWorld(t)
	req := SendRequest{Conversation: w.conv, IdempotencyKey: "sj1-durable", Message: Message{Text: "stable"}}
	good, e := w.a.Send(context.Background(), req)
	if e != nil || good.Outcome != ACK {
		t.Fatal("valid initial send", e)
	}
	path := filepath.Join(w.a.dir, "seam-send", sendFileName(req.IdempotencyKey))
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	for _, raw := range sj1Variants(string(original), "v", "1", "9") {
		if raw == string(original) {
			t.Fatal("fixture not applied")
		}
		if e := os.WriteFile(path, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		calls := w.r.Calls()
		got, e := w.a.Send(context.Background(), req)
		if e != nil || got.Outcome != UNKNOWN {
			t.Fatal("SJ1 corrupt durable retry admitted", e)
		}
		after, _ := os.ReadFile(path)
		if w.r.Calls() != calls || !bytes.Equal(after, []byte(raw)) {
			t.Fatal("refused retry changed relay or journal")
		}
	}
	if e := os.WriteFile(path, original, 0600); e != nil {
		t.Fatal(e)
	}
	got, e := w.a.Send(context.Background(), req)
	if e != nil || got.Outcome != ACK || got.Event != good.Event {
		t.Fatal("repaired retry", e)
	}
}

// Legacy send/cursor/conversation decoding also refuses all four key variants;
// refused reads preserve file bytes and existing cursor, while valid neighbors
// retain null slices and ordinary escaped string values.
func TestSJ1LegacyRecords(t *testing.T) {
	w := newSeamWorld(t)
	s := w.a.core.store
	rec := &sendRecord{ContentSHA: "ok", RumorID: "r", Rumor: json.RawMessage(`{"content":"a\nb"}`), Wraps: map[string]json.RawMessage{}, Stored: map[string]bool{}, CreatedAt: 1}
	good, _ := json.Marshal(rec)
	path := filepath.Join(s.dir, "send", sendFileName("sj1-legacy"))
	for _, raw := range sj1Variants(string(good), "content_sha256", `"ok"`, `null`) {
		if e := os.WriteFile(path, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		got, found, e := s.loadSend("sj1-legacy")
		after, _ := os.ReadFile(path)
		if seam.Code(e) != "invalid_reference" || got != nil || found || !bytes.Equal(after, []byte(raw)) {
			t.Fatal("SJ1 legacy send admitted or mutated")
		}
	}
	if e := os.WriteFile(path, good, 0600); e != nil {
		t.Fatal(e)
	}
	if got, found, e := s.loadSend("sj1-legacy"); e != nil || !found || !bytes.Equal(got.Rumor, rec.Rumor) {
		t.Fatal("valid legacy send", e)
	}
	cursor := `{"since":1,"wrap_ids":null,"rumor_ids":null}`
	cursorPath := filepath.Join(s.dir, "cursor.json")
	initial, _ := json.Marshal(w.a.core.cursor)
	for _, raw := range sj1Variants(cursor, "since", "1", "0") {
		if e := os.WriteFile(cursorPath, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := s.loadCursor(); seam.Code(e) != "invalid_reference" {
			t.Fatal("SJ1 legacy stored cursor admitted")
		}
		if _, e := w.a.core.stateFor(legacy.Cursor(raw)); e == nil {
			t.Fatal("SJ1 legacy explicit cursor admitted")
		}
		after, _ := os.ReadFile(cursorPath)
		state, _ := json.Marshal(w.a.core.cursor)
		if !bytes.Equal(after, []byte(raw)) || !bytes.Equal(initial, state) {
			t.Fatal("refused cursor changed state")
		}
	}
	if e := os.WriteFile(cursorPath, []byte(cursor), 0600); e != nil {
		t.Fatal(e)
	}
	if c, e := s.loadCursor(); e != nil || c.Since != 1 {
		t.Fatal("valid stored cursor", e)
	}
	if c, e := w.a.core.stateFor(legacy.Cursor(cursor)); e != nil || c.Since != 1 {
		t.Fatal("valid explicit cursor", e)
	}
	conv := `{"p":["` + w.a.core.Identity() + `"],"s":"a\nb"}`
	for _, raw := range sj1Variants(conv, "s", `"a\nb"`, `null`) {
		if _, e := parseConversation(legacy.ConversationID(raw)); e == nil {
			t.Fatal("SJ1 legacy conversation admitted")
		}
	}
	if c, e := parseConversation(legacy.ConversationID(conv)); e != nil || c.S != "a\nb" {
		t.Fatal("valid conversation", e)
	}
}

// A malformed later wrap cannot cause even the first valid recipient to be
// published or journaled. Repairing that wrap publishes the same valid batch.
func TestSJ1BatchBeforePublish(t *testing.T) {
	w := newSeamWorld(t)
	keys := []string{w.a.core.Identity(), w.b.core.Identity()}
	rumor, e := nostr.BuildRumor(w.a.core.cfg.Key, keys, nostr.KindRumor, "batch", nostr.RumorOptions{}, time.Now().Unix())
	if e != nil {
		t.Fatal(e)
	}
	wraps, e := nostr.WrapForRecipients(w.a.core.cfg.Key, rumor, keys, time.Now().Unix())
	if e != nil {
		t.Fatal(e)
	}
	first, _ := json.Marshal(wraps[0])
	last, _ := json.Marshal(wraps[1])
	for _, raw := range sj1Variants(string(last), "kind", "1059", "13") {
		rec := &sendRecord{RumorID: rumor.ID, Wraps: map[string]json.RawMessage{keys[0]: first, keys[1]: json.RawMessage(raw)}, Stored: map[string]bool{}}
		calls := w.r.Calls()
		_, ack, e := w.a.core.publishRecord(context.Background(), "sj1-batch", rec)
		if e == nil || !strings.Contains(e.Error(), "event json: invalid shape") || ack != legacy.AckUnknown {
			t.Fatal("SJ1 bad batch admitted", e)
		}
		if w.r.Calls() != calls || len(rec.Stored) != 0 {
			t.Fatal("SJ1 bad batch partially published")
		}
		if _, e := os.Stat(filepath.Join(w.a.core.store.dir, "send", sendFileName("sj1-batch"))); !os.IsNotExist(e) {
			t.Fatal("bad batch journaled")
		}
	}
	rec := &sendRecord{RumorID: rumor.ID, Wraps: map[string]json.RawMessage{keys[0]: first, keys[1]: last}, Stored: map[string]bool{}}
	w.a.core.cfg.WriteRelays = []string{w.r.URL}
	_, ack, e := w.a.core.publishRecord(context.Background(), "sj1-batch", rec)
	if e != nil || ack != legacy.AckOK || len(rec.Stored) != 2 {
		t.Fatal("valid batch neighbor", e)
	}
}
