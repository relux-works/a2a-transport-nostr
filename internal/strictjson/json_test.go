package strictjson

import (
	"encoding/json"
	"strings"
	"testing"
)

// Lexical and typed-key refusal leaves output untouched; nullable fields and
// escaped values remain legal. Bounds/trailing controls return the same safe code.
func TestSJ1Guard(t *testing.T) {
	type wire struct {
		Grant json.RawMessage `json:"grant"`
		Note  string          `json:"note"`
	}
	for _, raw := range []string{`{"grant":1,"grant":2}`, `{"grant":2,"grant":1}`, `{"grant":1,"gr\u0061nt":2}`, `{"gr\u0061nt":1}`, `{"grant":{"v":1,"v":2}}`, `{"grant":[{"v":2,"v":1}]}`, `{"grant":[{"\u0076":1}]}`, `{"Grant":1}`, `{"grant":1} {}`, strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66), string([]byte{'{', '"', 255, '"', ':', '1', '}'})} {
		out := wire{Grant: json.RawMessage("7"), Note: "retained"}
		if e := Unmarshal([]byte(raw), &out); e != ErrInvalid {
			t.Fatal("SJ1 ambiguous JSON admitted")
		}
		if string(out.Grant) != "7" || out.Note != "retained" {
			t.Fatal("refusal mutated destination")
		}
		if e := Unmarshal([]byte(`{"grant":null,"note":"a\nb"}`), &out); e != nil || out.Note != "a\nb" {
			t.Fatal("valid neighbor", e)
		}
	}
	var out struct {
		Entries map[string]struct {
			V int `json:"v"`
		} `json:"entries"`
	}
	if e := Unmarshal([]byte(`{"entries":{"x":{"V":1}}}`), &out); e != ErrInvalid {
		t.Fatal("typed map alias admitted")
	}
	if e := Unmarshal([]byte(`{"entries":{"x":{"v":1}}}`), &out); e != nil {
		t.Fatal("valid typed map", e)
	}
}

// The whole-input bound is inclusive; case-distinct opaque map keys are data,
// while escaped key spellings remain forbidden independently of schema.
func TestSJ1BoundsAndOpaqueKeys(t *testing.T) {
	atLimit := []byte(strings.Repeat(" ", MaxBytes-4) + "null")
	if Validate(atLimit) != nil || Validate(append(atLimit, ' ')) != ErrInvalid {
		t.Fatal("JSON input bound")
	}
	if Validate([]byte(`{"A":1,"a":2,"note":"a\nb"}`)) != nil {
		t.Fatal("opaque map keys folded")
	}
	if Validate([]byte(`{"A":1,"\u0061":2}`)) != ErrInvalid {
		t.Fatal("escaped opaque key admitted")
	}
}
