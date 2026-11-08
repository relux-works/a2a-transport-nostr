package nostrtransport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// sendRecord is the durable idempotency record for one Send: the
// exact signed rumor and per-recipient wraps, persisted before the
// first publish attempt. A retry re-publishes identical bytes.
type sendRecord struct {
	ContentSHA string                     `json:"content_sha256"`
	RumorID    string                     `json:"rumor_id"`
	Rumor      json.RawMessage            `json:"rumor"`
	Wraps      map[string]json.RawMessage `json:"wraps"` // recipient hex -> wrap event
	Stored     map[string]bool            `json:"stored"`
	CreatedAt  int64                      `json:"created_at"`
}

// cursorState is the persisted sync position: newest wrap time
// seen plus bounded seen-id sets, so a restart cannot redeliver.
type cursorState struct {
	Since      int64    `json:"since"`
	WrapIDs    []string `json:"wrap_ids"`
	RumorIDs   []string `json:"rumor_ids"`
	Tombstones []string `json:"tombstones,omitempty"`
}

const maxSeenIDs = 512

func (c *cursorState) seenWrap(id string) bool {
	for _, x := range c.WrapIDs {
		if x == id {
			return true
		}
	}
	return false
}

func (c *cursorState) seenRumor(id string) bool {
	for _, x := range c.RumorIDs {
		if x == id {
			return true
		}
	}
	return false
}

func (c *cursorState) tombstoned(id string) bool {
	for _, x := range c.Tombstones {
		if x == id {
			return true
		}
	}
	return false
}

func appendBounded(ids []string, id string) []string {
	ids = append(ids, id)
	if len(ids) > maxSeenIDs {
		ids = ids[len(ids)-maxSeenIDs:]
	}
	return ids
}

// store persists send records and the cursor under one state dir.
// Every write is temp file + fsync + rename + directory fsync.
type store struct {
	dir string
	mu  sync.Mutex
}

func openStore(dir string) (*store, error) {
	if dir == "" {
		return nil, fmt.Errorf("nostrtransport: state dir required")
	}
	if err := os.MkdirAll(filepath.Join(dir, "send"), 0700); err != nil {
		return nil, err
	}
	return &store{dir: dir}, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func writeFileFsync(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		return err
	}
	return syncDir(dir)
}

func sendFileName(idempotencyKey string) string {
	sum := sha256.Sum256([]byte(idempotencyKey))
	return hex.EncodeToString(sum[:]) + ".json"
}

func contentHash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *store) loadSend(idempotencyKey string) (*sendRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(filepath.Join(s.dir, "send", sendFileName(idempotencyKey)))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var rec sendRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, false, err
	}
	return &rec, true, nil
}

func (s *store) saveSend(idempotencyKey string, rec *sendRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeFileFsync(filepath.Join(s.dir, "send"), sendFileName(idempotencyKey), raw)
}

func (s *store) loadCursor() (cursorState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(filepath.Join(s.dir, "cursor.json"))
	if os.IsNotExist(err) {
		return cursorState{}, nil
	}
	if err != nil {
		return cursorState{}, err
	}
	var c cursorState
	return c, json.Unmarshal(raw, &c)
}

func (s *store) saveCursor(c cursorState) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeFileFsync(s.dir, "cursor.json", raw)
}
