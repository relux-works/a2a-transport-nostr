package nostr

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// PrivKey is a Nostr private key (secp256k1 scalar, BIP-340).
// The raw bytes are exposed only through explicit Bytes/Hex
// helpers for key-file persistence; String() is deliberately not
// defined so keys are never logged by accident.
type PrivKey struct {
	priv *btcec.PrivateKey
}

// GeneratePrivKey creates a fresh key from crypto/rand.
func GeneratePrivKey() (*PrivKey, error) {
	k, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	return &PrivKey{priv: k}, nil
}

// PrivKeyFromHex parses a 64-char hex private key. Zero and >= curve
// order are refused by btcec.
func PrivKeyFromHex(s string) (*PrivKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("privkey hex: %w", err)
	}
	return PrivKeyFromBytes(b)
}

// PrivKeyFromBytes parses a 32-byte private key.
func PrivKeyFromBytes(b []byte) (*PrivKey, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("privkey: want 32 bytes, got %d", len(b))
	}
	zero := true
	for _, c := range b {
		if c != 0 {
			zero = false
			break
		}
	}
	if zero {
		return nil, fmt.Errorf("privkey: zero scalar refused")
	}
	k, _ := btcec.PrivKeyFromBytes(b)
	if k == nil {
		return nil, fmt.Errorf("privkey: invalid scalar")
	}
	// PrivKeyFromBytes reduces mod N silently in some versions; refuse
	// anything that does not round-trip exactly (zero / >= N).
	if got := k.Serialize(); !equalBytes(got, b) {
		return nil, fmt.Errorf("privkey: scalar out of range")
	}
	return &PrivKey{priv: k}, nil
}

// Bytes returns the raw private key bytes. Caller must not log them.
func (k *PrivKey) Bytes() []byte {
	b := k.priv.Serialize()
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// Hex returns the raw private key as hex. Caller must not log it.
func (k *PrivKey) Hex() string { return hex.EncodeToString(k.Bytes()) }

// PubKeyHex returns the BIP-340 x-only public key as 64 lower hex.
func (k *PrivKey) PubKeyHex() string {
	return hex.EncodeToString(schnorr.SerializePubKey(k.priv.PubKey()))
}

// SignEvent fills e.PubKey, e.ID and e.Sig with a BIP-340 signature
// over the event id.
func (k *PrivKey) SignEvent(e *Event) error {
	e.PubKey = k.PubKeyHex()
	e.ID = e.ComputeID()
	idBytes, err := hex.DecodeString(e.ID)
	if err != nil {
		return err
	}
	sig, err := schnorr.Sign(k.priv, idBytes)
	if err != nil {
		return err
	}
	e.Sig = hex.EncodeToString(sig.Serialize())
	return nil
}

// VerifySignature checks e's id first, then the BIP-340 signature
// against e.PubKey. Both must hold; a valid signature over a wrong id
// (or vice versa) is refused.
func VerifySignature(e *Event) error {
	if e.Sig == "" {
		return fmt.Errorf("event has no signature")
	}
	if !e.CheckID() {
		return fmt.Errorf("event id mismatch")
	}
	pubBytes, err := hex.DecodeString(e.PubKey)
	if err != nil {
		return fmt.Errorf("pubkey hex: %w", err)
	}
	pub, err := schnorr.ParsePubKey(pubBytes)
	if err != nil {
		return fmt.Errorf("pubkey: %w", err)
	}
	sigBytes, err := hex.DecodeString(e.Sig)
	if err != nil {
		return fmt.Errorf("sig hex: %w", err)
	}
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	idBytes, _ := hex.DecodeString(e.ID)
	if !sig.Verify(idBytes, pub) {
		return fmt.Errorf("signature invalid")
	}
	return nil
}

// ParseXOnlyPubKey validates a hex x-only key is a real curve x.
func ParseXOnlyPubKey(hexKey string) error {
	b, err := hex.DecodeString(hexKey)
	if err != nil || len(b) != 32 {
		return fmt.Errorf("pubkey: want 64 hex")
	}
	_, err = schnorr.ParsePubKey(b)
	return err
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// RandomRead is crypto/rand, named for test injection symmetry.
func RandomRead(b []byte) error {
	_, err := rand.Read(b)
	return err
}
