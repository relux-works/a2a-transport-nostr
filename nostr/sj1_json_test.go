package nostr

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Wrapper, seal and rumor share ParseEvent. Ambiguous wire keys cannot reach
// signature verification; escaped content values remain valid Nostr text.
func TestSJ1EventKeys(t *testing.T) {
	for _, kind := range []string{"1059", "13", "14"} {
		valid := `{"id":"","pubkey":"` + strings.Repeat("a", 64) + `","created_at":1,"kind":` + kind + `,"tags":[],"content":"line\nvalue","sig":""}`
		for name, field := range map[string]string{
			"left-valid":        `"kind":` + kind + `,"kind":-1`,
			"right-valid":       `"kind":-1,"kind":` + kind,
			"escaped-duplicate": `"kind":-1,"k\u0069nd":` + kind,
			"escaped-single":    `"k\u0069nd":` + kind,
			"case-alias":        `"Kind":` + kind,
		} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				bad := strings.Replace(valid, `"kind":`+kind, field, 1)
				if e, err := ParseEvent([]byte(bad)); err == nil || e != nil {
					t.Fatal("SJ1 ambiguous event admitted")
				}
				if e, err := ParseEvent([]byte(valid)); err != nil || e.Content != "line\nvalue" {
					t.Fatal("valid neighbor refused", err)
				}
			})
		}
	}
}

// Genuine encrypted layers are signed correctly around malformed inner JSON.
// Refusal must occur at the named parse boundary, before sender admission.
func TestSJ1EncryptedKeys(t *testing.T) {
	sender, e := GeneratePrivKey()
	if e != nil {
		t.Fatal(e)
	}
	receiver, e := GeneratePrivKey()
	if e != nil {
		t.Fatal(e)
	}
	wrap, rumor, e := WrapDM(sender, receiver.PubKeyHex(), "line\nvalue", nil, 1000000)
	if e != nil {
		t.Fatal(e)
	}
	seal, e := SealRumor(sender, rumor, receiver.PubKeyHex(), 1000000)
	if e != nil {
		t.Fatal(e)
	}
	encrypt := func(raw []byte, key *PrivKey) string {
		t.Helper()
		ck, e := ConversationKey(key, receiver.PubKeyHex())
		if e != nil {
			t.Fatal(e)
		}
		out, e := EncryptNIP44(string(raw), ck, [32]byte{1})
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	rawWrap := func(raw []byte) *Event {
		t.Helper()
		ephemeral, e := GeneratePrivKey()
		if e != nil {
			t.Fatal(e)
		}
		v := &Event{Kind: KindGiftWrap, CreatedAt: 1000000, Tags: [][]string{{"p", receiver.PubKeyHex()}}, Content: encrypt(raw, ephemeral)}
		if e := ephemeral.SignEvent(v); e != nil {
			t.Fatal(e)
		}
		return v
	}
	for _, layer := range []string{"seal", "rumor"} {
		event := seal
		kind := "13"
		if layer == "rumor" {
			event = rumor
			kind = "14"
		}
		raw, e := json.Marshal(event)
		if e != nil {
			t.Fatal(e)
		}
		for _, field := range []string{`"kind":` + kind + `,"kind":0`, `"kind":0,"kind":` + kind, `"kind":` + kind + `,"k\u0069nd":0`, `"k\u0069nd":` + kind} {
			bad := []byte(strings.Replace(string(raw), `"kind":`+kind, field, 1))
			var hostile *Event
			if layer == "seal" {
				hostile = rawWrap(bad)
			} else {
				modified := *seal
				modified.Content = encrypt(bad, sender)
				if e := sender.SignEvent(&modified); e != nil {
					t.Fatal(e)
				}
				hostile, e = WrapSeal(&modified, receiver.PubKeyHex(), 1000000)
				if e != nil {
					t.Fatal(e)
				}
			}
			before, _ := json.Marshal(hostile)
			if got, e := UnwrapDM(hostile, receiver); e == nil || got != nil || !strings.HasPrefix(e.Error(), layer+" parse:") {
				t.Fatal("SJ1 encrypted JSON not refused at parse layer", e)
			}
			after, _ := json.Marshal(hostile)
			if !bytes.Equal(before, after) {
				t.Fatal("refusal mutated signed wrap")
			}
			if got, e := UnwrapDM(wrap, receiver); e != nil || got.SenderHex != sender.PubKeyHex() || got.Rumor.Content != "line\nvalue" {
				t.Fatal("valid encrypted neighbor", e)
			}
		}
	}
}
