package nostr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// FileCipher holds one AES-256-GCM encrypted file and its opening
// material for a kind 15 file message.
type FileCipher struct {
	Ciphertext []byte
	Key        []byte // 32 bytes
	Nonce      []byte // 12 bytes
	CipherSHA  string // sha256 hex of ciphertext ("x")
	PlainSHA   string // sha256 hex of plaintext ("ox")
}

// EncryptFile encrypts data under a fresh AES-256-GCM key.
func EncryptFile(data []byte) (*FileCipher, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, data, nil)
	cs := sha256.Sum256(ct)
	ps := sha256.Sum256(data)
	return &FileCipher{Ciphertext: ct, Key: key, Nonce: nonce,
		CipherSHA: hex.EncodeToString(cs[:]), PlainSHA: hex.EncodeToString(ps[:])}, nil
}

// DecryptFile verifies the ciphertext hash, opens the GCM seal,
// and verifies the plaintext hash. Any mismatch is an error.
func DecryptFile(ciphertext, key, nonce []byte, cipherSHA, plainSHA string) ([]byte, error) {
	cs := sha256.Sum256(ciphertext)
	if hex.EncodeToString(cs[:]) != cipherSHA {
		return nil, fmt.Errorf("file: ciphertext sha256 mismatch")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("file: %w", err)
	}
	ps := sha256.Sum256(plain)
	if hex.EncodeToString(ps[:]) != plainSHA {
		return nil, fmt.Errorf("file: plaintext sha256 mismatch")
	}
	return plain, nil
}

// FileTags renders kind 15 file metadata tags (NIP-17 file message).
func (f *FileCipher) FileTags(url, mime string) [][]string {
	return [][]string{
		{"file-type", mime},
		{"encryption-algorithm", "aes-gcm"},
		{"decryption-key", hex.EncodeToString(f.Key)},
		{"decryption-nonce", hex.EncodeToString(f.Nonce)},
		{"x", f.CipherSHA},
		{"ox", f.PlainSHA},
	}
}

// ParseFileTags extracts kind 15 file metadata from rumor tags.
// Content carries the URL per NIP-17.
func ParseFileTags(ev *Event) (url, mime, keyHex, nonceHex, cipherSHA, plainSHA string, ok bool) {
	url = ev.Content
	get := func(name string) string {
		v, _ := ev.TagFirst(name)
		return v
	}
	mime = get("file-type")
	keyHex = get("decryption-key")
	nonceHex = get("decryption-nonce")
	cipherSHA = get("x")
	plainSHA = get("ox")
	ok = get("encryption-algorithm") == "aes-gcm" &&
		url != "" && keyHex != "" && nonceHex != "" && cipherSHA != "" && plainSHA != ""
	return
}
