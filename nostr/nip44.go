package nostr

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/bits"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

// NIP-44 v2 constants.
const (
	nip44Version       = 2
	nip44MinPlaintext  = 1
	nip44MaxPlaintext  = 65535
	nip44MinPayloadB64 = 132
	nip44MaxPayloadB64 = 87472
)

// ConversationKey derives the NIP-44 v2 conversation key for (ourPriv,
// theirPubHex): HKDF-Extract(salt "nip44-v2", ECDH shared X) where the
// x-only peer key is lifted to the even-Y point.
func ConversationKey(ourPriv *PrivKey, theirPubHex string) ([32]byte, error) {
	var ck [32]byte
	pubBytes, err := hex.DecodeString(theirPubHex)
	if err != nil || len(pubBytes) != 32 {
		return ck, fmt.Errorf("nip44: peer pubkey want 64 hex")
	}
	lifted := make([]byte, 33)
	lifted[0] = 0x02
	copy(lifted[1:], pubBytes)
	pub, err := btcec.ParsePubKey(lifted)
	if err != nil {
		return ck, fmt.Errorf("nip44: peer pubkey: %w", err)
	}
	var point, result secp256k1.JacobianPoint
	pub.AsJacobian(&point)
	secp256k1.ScalarMultNonConst(&ourPriv.priv.Key, &point, &result)
	result.ToAffine()
	if (result.X.IsZero() && result.Y.IsZero()) || result.Z.IsZero() {
		return ck, fmt.Errorf("nip44: shared secret at infinity")
	}
	var shared [32]byte
	result.X.PutBytesUnchecked(shared[:])
	prk := hkdf.Extract(sha256.New, shared[:], []byte("nip44-v2"))
	copy(ck[:], prk)
	return ck, nil
}

func nip44MessageKeys(ck [32]byte, nonce [32]byte) (chachaKey, chachaNonce, hmacKey []byte, err error) {
	r := hkdf.Expand(sha256.New, ck[:], nonce[:])
	chachaKey = make([]byte, 32)
	chachaNonce = make([]byte, 12)
	hmacKey = make([]byte, 32)
	for _, dst := range [][]byte{chachaKey, chachaNonce, hmacKey} {
		if _, err = io.ReadFull(r, dst); err != nil {
			return nil, nil, nil, err
		}
	}
	return chachaKey, chachaNonce, hmacKey, nil
}

// nip44PaddedLen is the NIP-44 calc_padded_len in integer math.
func nip44PaddedLen(n int) int {
	if n <= 32 {
		return 32
	}
	nextPower := 1 << bits.Len(uint(n-1))
	chunk := nextPower / 8
	if chunk < 32 {
		chunk = 32
	}
	return chunk * ((n-1)/chunk + 1)
}

// EncryptNIP44 encrypts plaintext under a conversation key. A zero
// nonce means a fresh crypto/rand nonce; a nonzero nonce is used
// verbatim (test vectors).
func EncryptNIP44(plaintext string, ck [32]byte, nonce [32]byte) (string, error) {
	plain := []byte(plaintext)
	if len(plain) < nip44MinPlaintext || len(plain) > nip44MaxPlaintext {
		return "", fmt.Errorf("nip44: plaintext length %d out of range", len(plain))
	}
	if nonce == ([32]byte{}) {
		if err := RandomRead(nonce[:]); err != nil {
			return "", err
		}
	}
	chachaKey, chachaNonce, hmacKey, err := nip44MessageKeys(ck, nonce)
	if err != nil {
		return "", err
	}
	padded := make([]byte, 2+nip44PaddedLen(len(plain)))
	binary.BigEndian.PutUint16(padded, uint16(len(plain)))
	copy(padded[2:], plain)
	ciphertext, err := nip44ChaCha(chachaKey, chachaNonce, padded)
	if err != nil {
		return "", err
	}
	mac := nip44MAC(hmacKey, nonce, ciphertext)
	out := make([]byte, 0, 1+32+len(ciphertext)+32)
	out = append(out, nip44Version)
	out = append(out, nonce[:]...)
	out = append(out, ciphertext...)
	out = append(out, mac...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// DecryptNIP44 verifies the HMAC (constant time) before decrypting,
// then validates padding exactly. Any deviation is an error.
func DecryptNIP44(payload string, ck [32]byte) (string, error) {
	if len(payload) < nip44MinPayloadB64 || len(payload) > nip44MaxPayloadB64 {
		return "", fmt.Errorf("nip44: payload length %d out of range", len(payload))
	}
	if payload[0] == '#' {
		return "", fmt.Errorf("nip44: unknown version marker")
	}
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("nip44: base64: %w", err)
	}
	if len(decoded) < 99 || len(decoded) > 65603 {
		return "", fmt.Errorf("nip44: decoded length %d out of range", len(decoded))
	}
	if decoded[0] != nip44Version {
		return "", fmt.Errorf("nip44: unknown version %d", decoded[0])
	}
	var nonce [32]byte
	copy(nonce[:], decoded[1:33])
	ciphertext := decoded[33 : len(decoded)-32]
	givenMAC := decoded[len(decoded)-32:]
	chachaKey, chachaNonce, hmacKey, err := nip44MessageKeys(ck, nonce)
	if err != nil {
		return "", err
	}
	if !hmac.Equal(givenMAC, nip44MAC(hmacKey, nonce, ciphertext)) {
		return "", fmt.Errorf("nip44: hmac mismatch")
	}
	padded, err := nip44ChaCha(chachaKey, chachaNonce, ciphertext)
	if err != nil {
		return "", err
	}
	n := int(binary.BigEndian.Uint16(padded[0:2]))
	if n < nip44MinPlaintext || n > nip44MaxPlaintext || len(padded) != 2+nip44PaddedLen(n) {
		return "", fmt.Errorf("nip44: invalid padding")
	}
	return string(padded[2 : 2+n]), nil
}

func nip44ChaCha(key, nonce, msg []byte) ([]byte, error) {
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(msg))
	c.XORKeyStream(dst, msg)
	return dst, nil
}

func nip44MAC(key []byte, nonce [32]byte, ciphertext []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(nonce[:])
	h.Write(ciphertext)
	return h.Sum(nil)
}
