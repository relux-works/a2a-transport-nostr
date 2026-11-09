package nostrtransport

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"

	"relux.works/a2a-transport-nostr/nostr"
)

type privateMedia struct {
	Version   int    `json:"v"`
	URL       string `json:"url"`
	MIME      string `json:"mime"`
	CipherSHA string `json:"cipher_sha"`
	PlainSHA  string `json:"plain_sha"`
	Key       string `json:"key"`
	Nonce     string `json:"nonce"`
	Size      int64  `json:"size"`
}

func (m privateMedia) tags() [][]string {
	return [][]string{{"file-type", m.MIME}, {"encryption-algorithm", "aes-gcm"}, {"decryption-key", m.Key}, {"decryption-nonce", m.Nonce}, {"x", m.CipherSHA}, {"ox", m.PlainSHA}}
}
func decodeMedia(raw []byte) (privateMedia, error) {
	var m privateMedia
	if len(raw) > 4096 || strictJSON(raw, &m) != nil || m.Version != 1 || !hexID(m.CipherSHA) || !hexID(m.PlainSHA) || !hexID(m.Key) || len(m.Nonce) != 24 || m.Size < 0 || m.Size > maxMedia || len(m.MIME) > 128 {
		return m, seamError("invalid_reference")
	}
	if _, e := hex.DecodeString(m.Nonce); e != nil {
		return m, seamError("invalid_reference")
	}
	b, _ := json.Marshal([]string{m.URL})
	if _, e := settingURLs(string(b), false); e != nil {
		return m, seamError("invalid_reference")
	}
	return m, nil
}
func (a *Adapter) Upload(ctx context.Context, r io.Reader, meta MediaMeta) (MediaRef, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || ctx.Err() != nil {
		return MediaRef{}, seamError("unavailable")
	}
	if r == nil || meta.Size < 0 || meta.Size > maxMedia || len(meta.ContentType) > 128 {
		return MediaRef{}, seamError("invalid_reference")
	}
	data, e := io.ReadAll(io.LimitReader(r, maxMedia+1))
	if e != nil || ctx.Err() != nil {
		return MediaRef{}, seamError("unavailable")
	}
	if len(data) > maxMedia {
		return MediaRef{}, seamError("content_too_large")
	}
	if meta.Size != 0 && meta.Size != int64(len(data)) || meta.SHA256 != "" && meta.SHA256 != digest(data) {
		return MediaRef{}, seamError("invalid_reference")
	}
	fc, e := nostr.EncryptFile(data)
	if e != nil {
		return MediaRef{}, seamError("unavailable")
	}
	for _, server := range a.core.cfg.BlossomServers {
		hash, _, e := a.core.blossom.Put(ctx, server, fc.Ciphertext)
		if e != nil {
			continue
		}
		// Never accept a server's redirecting URL as part of a private reference.
		m := privateMedia{Version: 1, URL: strings.TrimSuffix(server, "/") + "/" + hash, MIME: meta.ContentType, CipherSHA: fc.CipherSHA, PlainSHA: fc.PlainSHA, Key: hex.EncodeToString(fc.Key), Nonce: hex.EncodeToString(fc.Nonce), Size: int64(len(data))}
		raw, _ := json.Marshal(m)
		return mediaRef(string(raw)), nil
	}
	return MediaRef{}, seamError("unavailable")
}
func (a *Adapter) Download(ctx context.Context, ref MediaRef, w io.Writer, limit int64) (MediaMeta, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || ctx.Err() != nil {
		return MediaMeta{}, seamError("unavailable")
	}
	m, e := decodeMedia([]byte(ref.Opaque()))
	if e != nil {
		return MediaMeta{}, e
	}
	if w == nil || limit < 0 || limit > maxMedia || m.Size > limit {
		return MediaMeta{}, seamError("content_too_large")
	}
	// Fetch by ciphertext hash only from explicitly configured servers. A received
	// URL cannot steer privileged network access or disclose the reference key.
	var ct []byte
	for _, server := range a.core.cfg.BlossomServers {
		ct, e = a.core.blossom.Get(ctx, server, m.CipherSHA)
		if e == nil {
			break
		}
	}
	if e != nil || ct == nil || int64(len(ct)) != m.Size+16 {
		return MediaMeta{}, seamError("unavailable")
	}
	key, _ := hex.DecodeString(m.Key)
	nonce, _ := hex.DecodeString(m.Nonce)
	plain, e := nostr.DecryptFile(ct, key, nonce, m.CipherSHA, m.PlainSHA)
	if e != nil || int64(len(plain)) != m.Size {
		return MediaMeta{}, seamError("invalid_reference")
	}
	if ctx.Err() != nil {
		return MediaMeta{}, seamError("unavailable")
	}
	n, e := w.Write(plain)
	if e != nil || n != len(plain) {
		return MediaMeta{}, seamError("unavailable")
	}
	return MediaMeta{ContentType: m.MIME, SHA256: m.PlainSHA, Size: m.Size}, nil
}
