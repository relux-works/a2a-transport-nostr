package nostrtransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"relux.works/a2a-transport-nostr/nostr"
)

const (
	// Two nested NIP44 encryptions: the signed seal JSON must also fit 65535.
	// Worst-case JSON escaping uses six bytes per content byte. Reserve envelope
	// and bounded metadata at both layers; check the actual serialized layers too.
	seamMaxContent = 4096
	maxParties     = 16
	maxMedia       = 8 << 20
	syncWindow     = int64((48*time.Hour + 15*time.Minute) / time.Second)
)

// Adapter implements T0 using the reviewed Nostr primitives. The legacy
// Transport remains available for old callers; it is not the seam adapter.
type Adapter struct {
	mu      sync.Mutex
	core    *Transport
	dir     string
	lock    *os.File
	closed  bool
	dropped uint64
	now     func() time.Time
}

var _ SeamTransport = (*Adapter)(nil)

// Open owns one identity exclusively. Settings contain only explicit relay
// lists (JSON arrays), never private keys or paths outside StateDir.
func Open(cfg SeamConfig) (*Adapter, error) {
	for k := range cfg.Settings {
		switch k {
		case "read_relays", "write_relays", "dm_relays", "discovery_relays", "blossom_servers":
		default:
			return nil, seamError("invalid_reference")
		}
	}
	read, err := settingURLs(cfg.Settings["read_relays"], true)
	if err != nil {
		return nil, err
	}
	write, err := settingURLs(cfg.Settings["write_relays"], true)
	if err != nil {
		return nil, err
	}
	dm, err := settingURLs(cfg.Settings["dm_relays"], true)
	if err != nil {
		return nil, err
	}
	discovery, err := settingURLs(cfg.Settings["discovery_relays"], true)
	if err != nil {
		return nil, err
	}
	blobs, err := settingURLs(cfg.Settings["blossom_servers"], false)
	if err != nil {
		return nil, err
	}
	if len(read) == 0 && len(write) == 0 {
		return nil, seamError("invalid_reference")
	}
	if !filepath.IsAbs(cfg.StateDir) {
		return nil, seamError("invalid_reference")
	}
	// The supplied root must not be a symlink. Existing broad roots are refused,
	// not chmodded: ownership of a different directory is never inferred.
	if err := privateDir(cfg.StateDir); err != nil {
		return nil, err
	}
	if resolved, e := filepath.EvalSymlinks(cfg.StateDir); e != nil || resolved != filepath.Clean(cfg.StateDir) {
		return nil, seamError("invalid_reference")
	}
	lockPath := filepath.Join(cfg.StateDir, "seam.lock")
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, seamError("unavailable")
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	if st, e := lock.Stat(); e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		lock.Close()
		return nil, seamError("unavailable")
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, seamError("unavailable")
	}
	fail := func(e error) (*Adapter, error) { syscall.Flock(fd, syscall.LOCK_UN); lock.Close(); return nil, e }
	// The legacy prototype's cursor is not this adapter's state. Do not read or
	// migrate it implicitly (in particular, never follow an old cursor symlink).
	if _, e := os.Lstat(filepath.Join(cfg.StateDir, "cursor.json")); !os.IsNotExist(e) {
		return fail(seamError("unavailable"))
	}
	for _, d := range []string{"send", "seam-send", "seam-events"} {
		if err := privateDir(filepath.Join(cfg.StateDir, d)); err != nil {
			return fail(err)
		}
	}
	keyPath := filepath.Join(cfg.StateDir, "identity.key")
	var key *nostr.PrivKey
	if info, e := os.Lstat(keyPath); os.IsNotExist(e) {
		if _, e := os.Lstat(filepath.Join(cfg.StateDir, "seam.identity")); !os.IsNotExist(e) {
			return fail(seamError("unauthenticated"))
		}
		key, err = nostr.GeneratePrivKey()
		if err == nil {
			err = writeFileFsync(cfg.StateDir, "identity.key", []byte(key.Hex()+"\n"))
		}
	} else if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return fail(seamError("unauthenticated"))
	} else {
		key, err = LoadKey(keyPath)
	}
	if err != nil {
		return fail(seamError("unauthenticated"))
	}
	core, err := New(Config{Key: key, StateDir: cfg.StateDir, ReadRelays: read, WriteRelays: write, DMRelays: dm, DiscoveryRelays: discovery, BlossomServers: blobs})
	if err != nil {
		return fail(seamError("unavailable"))
	}
	a := &Adapter{core: core, dir: cfg.StateDir, lock: lock, now: time.Now}
	// Bind persistent records to this identity; replacement keys cannot replay
	// another sender's journal or silently take over its inbox.
	binding := []byte(key.PubKeyHex())
	if old, e := readPrivate(filepath.Join(cfg.StateDir, "seam.identity"), 128); os.IsNotExist(e) {
		err = writeFileFsync(cfg.StateDir, "seam.identity", binding)
	} else if e != nil || !bytes.Equal(old, binding) {
		err = seamError("unauthenticated")
	}
	if err != nil {
		core.Close()
		return fail(seamError("unauthenticated"))
	}
	return a, nil
}
func privateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return seamError("unavailable")
	}
	st, err := os.Lstat(path)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return seamError("unavailable")
	}
	return nil
}
func readPrivate(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > limit {
		return nil, seamError("unavailable")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(b)) > limit {
		return nil, seamError("unavailable")
	}
	return b, err
}
func settingURLs(raw string, ws bool) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var out []string
	if json.Unmarshal([]byte(raw), &out) != nil || len(out) > 16 {
		return nil, seamError("invalid_reference")
	}
	for _, s := range out {
		u, e := url.Parse(s)
		if e != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(s) > 2048 {
			return nil, seamError("invalid_reference")
		}
		if ws {
			if u.Scheme != "ws" && u.Scheme != "wss" {
				return nil, seamError("invalid_reference")
			}
		} else if u.Scheme != "http" && u.Scheme != "https" {
			return nil, seamError("invalid_reference")
		}
	}
	return nostr.SortedUnique(out), nil
}
func (a *Adapter) Self(context.Context) (Principal, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return Principal{}, seamError("unavailable")
	}
	return Principal{ID: PrincipalID(a.core.Identity())}, nil
}
func (a *Adapter) Caps() Capabilities {
	return Capabilities{Redaction: redactionNone, Membership: membershipSenderSide, Threads: true, IdempotentRetry: true, MaxContentBytes: seamMaxContent}
}
func (a *Adapter) ConversationCaps(_ context.Context, c ConversationID) (ConversationCaps, error) {
	if _, e := a.conversation(c); e != nil {
		return ConversationCaps{}, e
	}
	return ConversationCaps{E2EE: true}, nil
}
func (a *Adapter) Addressing() Addressing { return a }
func (a *Adapter) Principal(ref string) (PrincipalID, error) {
	if len(ref) != 64 || strings.ToLower(ref) != ref || nostr.ParseXOnlyPubKey(ref) != nil {
		return "", seamError("invalid_reference")
	}
	return PrincipalID(ref), nil
}
func (a *Adapter) Format(p PrincipalID) string {
	if _, err := a.Principal(string(p)); err != nil {
		return "nostr:invalid"
	}
	return string(p)
}
func (a *Adapter) Conversation(_ context.Context, ref string) (ConversationID, error) {
	c := ConversationID(ref)
	_, e := a.conversation(c)
	return c, e
}

// ConversationFor returns the canonical participant-set ID, including self.
func (a *Adapter) ConversationFor(parties []PrincipalID, subject string) (ConversationID, error) {
	p := []string{a.core.Identity()}
	for _, v := range parties {
		p = append(p, string(v))
	}
	b, _ := json.Marshal(convJSON{P: nostr.SortedUnique(p), S: subject})
	c := ConversationID(b)
	_, err := a.conversation(c)
	return c, err
}
func (a *Adapter) conversation(c ConversationID) (convJSON, error) {
	var v convJSON
	if len(c) > 4096 || strictJSON([]byte(c), &v) != nil || len(v.P) < 1 || len(v.P) > maxParties || len(v.S) > 128 || !utf8.ValidString(v.S) {
		return v, seamError("invalid_reference")
	}
	self := false
	for _, p := range v.P {
		if _, err := a.Principal(p); err != nil {
			return v, err
		}
		self = self || p == a.core.Identity()
	}
	canonical, _ := json.Marshal(convJSON{P: nostr.SortedUnique(v.P), S: v.S})
	if !self || string(canonical) != string(c) {
		return v, seamError("invalid_reference")
	}
	return v, nil
}
func strictJSON(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return seamError("invalid_reference")
	}
	return nil
}
func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func (a *Adapter) Members(_ context.Context, c ConversationID) ([]Member, error) {
	v, e := a.conversation(c)
	if e != nil {
		return nil, e
	}
	out := make([]Member, len(v.P))
	for i, p := range v.P {
		out[i] = Member{ID: PrincipalID(p)}
	}
	return out, nil
}
func (a *Adapter) Dropped() uint64 { a.mu.Lock(); defer a.mu.Unlock(); return a.dropped }
func (a *Adapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	a.core.Close()
	syscall.Flock(int(a.lock.Fd()), syscall.LOCK_UN)
	if a.lock.Close() != nil {
		return seamError("unavailable")
	}
	return nil
}
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
