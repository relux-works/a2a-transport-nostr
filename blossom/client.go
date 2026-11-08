// Package blossom is a minimal Blossom client (BUD-01 download,
// BUD-02 upload with a kind 24242 authorization event). Blobs are
// sha256-addressed; downloads are always hash-verified.
package blossom

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"relux.works/a2a-transport-nostr/nostr"
)

// Client talks to Blossom servers. Signer authorizes uploads.
type Client struct {
	HTTP   *http.Client
	Signer *nostr.PrivKey
	Now    func() time.Time
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// AuthHeader builds the BUD-02 authorization header value for one
// action ("upload") bound to one blob hash.
func (c *Client) AuthHeader(action, sha256hex string) (string, error) {
	if c.Signer == nil {
		return "", fmt.Errorf("blossom: no signer configured")
	}
	now := c.now().Unix()
	ev := &nostr.Event{
		CreatedAt: now, Kind: nostr.KindBlossomAuth, Content: "",
		Tags: [][]string{
			{"t", action},
			{"x", sha256hex},
			{"expiration", fmt.Sprint(now + 300)},
		},
	}
	if err := c.Signer.SignEvent(ev); err != nil {
		return "", err
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return "", err
	}
	return "Nostr " + base64.StdEncoding.EncodeToString(raw), nil
}

// Put uploads data to one server and returns its sha256 and URL.
// The hash is computed locally; a server reporting a different
// hash is an error.
func (c *Client) Put(ctx context.Context, server string, data []byte) (hash, url string, err error) {
	sum := sha256.Sum256(data)
	hash = hex.EncodeToString(sum[:])
	auth, err := c.AuthHeader("upload", hash)
	if err != nil {
		return "", "", err
	}
	server = strings.TrimSuffix(server, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		server+"/upload", bytes.NewReader(data))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.http().Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("blossom: upload status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var desc struct {
		SHA256 string `json:"sha256"`
		URL    string `json:"url"`
	}
	_ = json.Unmarshal(body, &desc)
	if desc.SHA256 != "" && desc.SHA256 != hash {
		return "", "", fmt.Errorf("blossom: server reported hash %s, want %s", desc.SHA256, hash)
	}
	url = desc.URL
	if url == "" {
		url = server + "/" + hash
	}
	return hash, url, nil
}

// Get downloads a blob by hash from one server and verifies it.
func (c *Client) Get(ctx context.Context, server, hash string) ([]byte, error) {
	return c.GetURL(ctx, strings.TrimSuffix(server, "/")+"/"+hash, hash)
}

// GetURL downloads a full blob URL and verifies the hash.
func (c *Client) GetURL(ctx context.Context, url, wantSHA string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("blossom: download status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != wantSHA {
		return nil, fmt.Errorf("blossom: hash mismatch for %s", wantSHA)
	}
	return data, nil
}
