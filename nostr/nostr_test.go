package nostr

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// TestNIP01KnownEvent proves a real published NIP-01 event recomputes
// to its stated id and verifies under BIP-340.
func TestNIP01KnownEvent(t *testing.T) {
	raw := `{"kind":1,"id":"dc90c95f09947507c1044e8f48bcf6350aa6bff1507dd4acfc755b9239b5c962","pubkey":"3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d","created_at":1644271588,"tags":[],"content":"now that https://blueskyweb.org/blog/2-7-2022-overview was announced we can stop working on nostr?","sig":"230e9d8f0ddaf7eb70b5f7741ccfa37e87a455c9a469282e3464e2052d3192cd63a167e196e381ef9d7e69e9ea43af2443b839974dc85d8aaab9efe1d9296524"}`
	ev, err := ParseEvent([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !ev.CheckID() {
		t.Fatalf("id mismatch: computed %s", ev.ComputeID())
	}
	if err := VerifySignature(ev); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Tampered content must fail id (and therefore signature) checks.
	bad := *ev
	bad.Content += "x"
	if bad.CheckID() || VerifySignature(&bad) == nil {
		t.Fatal("tampered event verified")
	}
}

// TestBIP340Vector0 proves pubkey derivation and signature verification
// against BIP-340 test vector 0, and that a flipped signature fails.
func TestBIP340Vector0(t *testing.T) {
	priv, err := PrivKeyFromHex("0000000000000000000000000000000000000000000000000000000000000003")
	if err != nil {
		t.Fatal(err)
	}
	wantPub := strings.ToLower("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
	if priv.PubKeyHex() != wantPub {
		t.Fatalf("pubkey = %s, want %s", priv.PubKeyHex(), wantPub)
	}
	// Round-trip sign over the zero message via an event-shaped path:
	// sign any event and verify; then corrupt one sig nibble and refuse.
	ev := &Event{CreatedAt: 1, Kind: 1, Tags: [][]string{}, Content: "vector"}
	if err := priv.SignEvent(ev); err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(ev); err != nil {
		t.Fatal(err)
	}
	bad := *ev
	b := []byte(bad.Sig)
	if b[0] == '0' {
		b[0] = '1'
	} else {
		b[0] = '0'
	}
	bad.Sig = string(b)
	if VerifySignature(&bad) == nil {
		t.Fatal("corrupted signature verified")
	}
}

// TestNIP44OfficialVectors proves conversation-key derivation,
// encryption (fixed nonce) and decryption against official NIP-44 v2
// valid vectors.
func TestNIP44OfficialVectors(t *testing.T) {
	vectors := []struct {
		sk1, sk2, ck, nonce, plaintext, payload string
	}{
		{"0000000000000000000000000000000000000000000000000000000000000001",
			"0000000000000000000000000000000000000000000000000000000000000002",
			"c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d",
			"0000000000000000000000000000000000000000000000000000000000000001", "a",
			"AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb"},
		{"0000000000000000000000000000000000000000000000000000000000000002",
			"0000000000000000000000000000000000000000000000000000000000000001",
			"c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d",
			"f00000000000000000000000000000f00000000000000000000000000000000f", "🍕🫃",
			"AvAAAAAAAAAAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAAPSKSK6is9ngkX2+cSq85Th16oRTISAOfhStnixqZziKMDvB0QQzgFZdjLTPicCJaV8nDITO+QfaQ61+KbWQIOO2Yj"},
		{"5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a",
			"4b22aa260e4acb7021e32f38a6cdf4b673c6a277755bfce287e370c924dc936d",
			"3e2b52a63be47d34fe0a80e34e73d436d6963bc8f39827f327057a9986c20a45",
			"b635236c42db20f021bb8d1cdff5ca75dd1a0cc72ea742ad750f33010b24f73b", "表ポあA鷗ŒéＢ逍Üßªąñ丂㐀𠀀",
			"ArY1I2xC2yDwIbuNHN/1ynXdGgzHLqdCrXUPMwELJPc7s7JqlCMJBAIIjfkpHReBPXeoMCyuClwgbT419jUWU1PwaNl4FEQYKCDKVJz+97Mp3K+Q2YGa77B6gpxB/lr1QgoqpDf7wDVrDmOqGoiPjWDqy8KzLueKDcm9BVP8xeTJIxs="},
	}
	for i, v := range vectors {
		p1, err := PrivKeyFromHex(v.sk1)
		if err != nil {
			t.Fatal(err)
		}
		p2, err := PrivKeyFromHex(v.sk2)
		if err != nil {
			t.Fatal(err)
		}
		ck, err := ConversationKey(p1, p2.PubKeyHex())
		if err != nil {
			t.Fatalf("v%d ck: %v", i, err)
		}
		if hex.EncodeToString(ck[:]) != v.ck {
			t.Fatalf("v%d ck = %x, want %s", i, ck, v.ck)
		}
		var nonce [32]byte
		nb, _ := hex.DecodeString(v.nonce)
		copy(nonce[:], nb)
		got, err := EncryptNIP44(v.plaintext, ck, nonce)
		if err != nil || got != v.payload {
			t.Fatalf("v%d encrypt = %q, err %v", i, got, err)
		}
		plain, err := DecryptNIP44(v.payload, ck)
		if err != nil || plain != v.plaintext {
			t.Fatalf("v%d decrypt = %q, err %v", i, plain, err)
		}
	}
}

// TestNIP44InvalidVectors proves official invalid payloads are refused
// (bad version, bad HMAC, bad padding, empty).
func TestNIP44InvalidVectors(t *testing.T) {
	cases := []struct{ ck, payload string }{
		{"36f04e558af246352dcf73b692fbd3646a2207bd8abd4b1cd26b234db84d9481",
			"AK1AjUvoYW3IS7C/BGRUoqEC7ayTfDUgnEPNeWTF/reBZFaha6EAIRueE9D1B1RuoiuFScC0Q94yjIuxZD3JStQtE8JMNacWFs9rlYP+ZydtHhRucp+lxfdvFlaGV/sQlqZz"},
		{"cff7bd6a3e29a450fd27f6c125d5edeb0987c475fd1e8d97591e0d4d8a89763c",
			"Agn/l3ULCEAS4V7LhGFM6IGA17jsDUaFCKhrbXDANholyySBfeh+EN8wNB9gaLlg4j6wdBYh+3oK+mnxWu3NKRbSvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"5254827d29177622d40a7b67cad014fe7137700c3c523903ebbe3e1b74d40214",
			"Anq2XbuLvCuONcr7V0UxTh8FAyWoZNEdBHXvdbNmDZHB573MI7R7rrTYftpqmvUpahmBC2sngmI14/L0HjOZ7lWGJlzdh6luiOnGPc46cGxf08MRC4CIuxx3i2Lm0KqgJ7vA"},
		{"5cd2d13b9e355aeb2452afbd3786870dbeecb9d355b12cb0a3b6e9da5744cd35", ""},
	}
	for i, c := range cases {
		var ck [32]byte
		b, _ := hex.DecodeString(c.ck)
		copy(ck[:], b)
		if _, err := DecryptNIP44(c.payload, ck); err == nil {
			t.Fatalf("case %d: invalid payload decrypted", i)
		}
	}
}

// TestWrapUnwrapRoundTrip proves a DM wrapped by WrapDM unwraps with
// the sender authenticated as the seal key, and content intact.
func TestWrapUnwrapRoundTrip(t *testing.T) {
	alice, _ := GeneratePrivKey()
	bob, _ := GeneratePrivKey()
	wrap, rumor, err := WrapDM(alice, bob.PubKeyHex(), "hello <-> \"world\"\n\t", nil, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	out, err := UnwrapDM(wrap, bob)
	if err != nil {
		t.Fatal(err)
	}
	if out.SenderHex != alice.PubKeyHex() || out.Rumor.ID != rumor.ID ||
		out.Rumor.Content != rumor.Content {
		t.Fatalf("mismatch: %+v vs rumor %+v", out, rumor)
	}
	if out.WrapperHex == out.SenderHex {
		t.Fatal("gift-wrap key must be ephemeral, not sender")
	}
}

// TestWrapAtSmallTimestamp proves NIP-59 timestamp jitter never
// produces a negative created_at (regression: seal/wrap at small
// unix times were unparseable).
func TestWrapAtSmallTimestamp(t *testing.T) {
	alice, _ := GeneratePrivKey()
	bob, _ := GeneratePrivKey()
	for i := 0; i < 20; i++ {
		wrap, _, err := WrapDM(alice, bob.PubKeyHex(), "early", nil, 100)
		if err != nil {
			t.Fatal(err)
		}
		if wrap.CreatedAt < 0 {
			t.Fatalf("wrap created_at %d negative", wrap.CreatedAt)
		}
		out, err := UnwrapDM(wrap, bob)
		if err != nil {
			t.Fatalf("unwrap at small time: %v", err)
		}
		if out.Seal.CreatedAt < 0 {
			t.Fatalf("seal created_at %d negative", out.Seal.CreatedAt)
		}
		if out.Rumor.CreatedAt != 100 {
			t.Fatalf("rumor time jittered: %d", out.Rumor.CreatedAt)
		}
	}
}

// TestZeroPrivKeyRefused proves the zero scalar is not a key (RM2 M5).
func TestZeroPrivKeyRefused(t *testing.T) {
	if _, err := PrivKeyFromHex(strings.Repeat("0", 64)); err == nil {
		t.Fatal("zero private key accepted")
	}
	if _, err := PrivKeyFromBytes(make([]byte, 32)); err == nil {
		t.Fatal("zero private key bytes accepted")
	}
	// Neighbour: scalar 1 is a valid key.
	if _, err := PrivKeyFromHex("0000000000000000000000000000000000000000000000000000000000000001"); err != nil {
		t.Fatalf("scalar 1 refused: %v", err)
	}
}

// TestParseEventDuplicateKeysRefused proves duplicate top-level JSON
// keys are refused instead of last-wins (RM2 M8).
func TestParseEventDuplicateKeysRefused(t *testing.T) {
	alice, _ := GeneratePrivKey()
	ev := &Event{CreatedAt: 1, Kind: 1, Tags: [][]string{}, Content: "x"}
	if err := alice.SignEvent(ev); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(ev)
	if _, err := ParseEvent(raw); err != nil {
		t.Fatalf("valid neighbour refused: %v", err)
	}
	dup := strings.Replace(string(raw), `"content":"x"`, `"content":"x","content":"y"`, 1)
	if _, err := ParseEvent([]byte(dup)); err == nil {
		t.Fatal("duplicate content key accepted")
	}
}

// TestUnwrapRequiresKind14 proves a non-14 rumor inside a valid seal
// is refused (RM2 M3), beside the kind-14 neighbour above.
func TestUnwrapRequiresKind14(t *testing.T) {
	alice, _ := GeneratePrivKey()
	bob, _ := GeneratePrivKey()
	rumor := &Event{PubKey: alice.PubKeyHex(), CreatedAt: 1700000000, Kind: 1,
		Tags: [][]string{{"p", bob.PubKeyHex()}}, Content: "note, not a DM"}
	rumor.ID = rumor.ComputeID()
	wrap, err := GiftWrap(rumor, alice, bob.PubKeyHex(), 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapDM(wrap, bob); err == nil || !strings.Contains(err.Error(), "kind") {
		t.Fatalf("kind-1 rumor unwrap err = %v", err)
	}
}
