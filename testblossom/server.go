// Package testblossom is an in-process Blossom server (BUD-01/02)
// on 127.0.0.1 for conformance tests. Uploads require a valid
// kind 24242 authorization event bound to the blob hash.
package testblossom

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"relux.works/a2a-transport-nostr/nostr"
)

// Server holds blobs in memory, keyed by sha256 hex.
type Server struct {
	URL string

	ln     net.Listener
	server *http.Server
	mu     sync.Mutex
	blobs  map[string][]byte
	puts   int
	// CorruptOnGet flips one byte of every download (hash-mismatch control).
	CorruptOnGet bool
}

// Start binds a random 127.0.0.1 port and serves.
func Start() (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{URL: fmt.Sprintf("http://%s", ln.Addr().String()),
		ln: ln, blobs: map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/upload", s.upload)
	mux.HandleFunc("/", s.download)
	s.server = &http.Server{Handler: mux}
	go func() { _ = s.server.Serve(ln) }()
	return s, nil
}

// Close shuts the server down.
func (s *Server) Close() {
	if s.server != nil {
		_ = s.server.Close()
	}
	_ = s.ln.Close()
}

// Puts returns how many uploads were accepted.
func (s *Server) Puts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.puts
}

func checkAuth(r *http.Request, wantSHA string) error {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Nostr ") {
		return fmt.Errorf("missing authorization")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Nostr "))
	if err != nil {
		return err
	}
	ev, err := nostr.ParseEvent(raw)
	if err != nil {
		return err
	}
	if ev.Kind != nostr.KindBlossomAuth {
		return fmt.Errorf("wrong auth kind")
	}
	if err := nostr.VerifySignature(ev); err != nil {
		return err
	}
	if v, _ := ev.TagFirst("t"); v != "upload" {
		return fmt.Errorf("wrong auth action")
	}
	if v, _ := ev.TagFirst("x"); v != wantSHA {
		return fmt.Errorf("auth hash mismatch")
	}
	expStr, _ := ev.TagFirst("expiration")
	exp, _ := strconv.ParseInt(expStr, 10, 64)
	if exp <= time.Now().Unix() {
		return fmt.Errorf("auth expired")
	}
	return nil
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "PUT only", http.StatusMethodNotAllowed)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	if err := checkAuth(r, sha); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	s.blobs[sha] = data
	s.puts++
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"sha256": sha, "size": len(data), "url": s.URL + "/" + sha,
	})
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	sha := strings.TrimPrefix(r.URL.Path, "/")
	s.mu.Lock()
	data, ok := s.blobs[sha]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	out := data
	if s.CorruptOnGet && len(out) > 0 {
		out = append([]byte(nil), out...)
		out[0] ^= 0xff
	}
	_, _ = w.Write(out)
}
