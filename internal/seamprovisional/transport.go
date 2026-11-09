// Package seamprovisional is a disposable T0 contract sketch. Upstream T0 wins.
// It contains no transport-specific behavior and is deleted when T0 lands.
package seamprovisional

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

const APIVersion = 1

type ConversationID string
type EventID string
type PrincipalID string
type Cursor []byte
type Principal struct {
	ID          PrincipalID
	DisplayName string
}
type Outcome string

const (
	ACK     Outcome = "ACK"
	UNKNOWN Outcome = "UNKNOWN"
	REFUSED Outcome = "REFUSED"
)

type RedactionMode string

const (
	None       RedactionMode = "none"
	BestEffort RedactionMode = "best_effort"
	Enforced   RedactionMode = "enforced"
)

type MembershipMode string

const (
	SenderSide     MembershipMode = "sender_side"
	ServerEnforced MembershipMode = "server_enforced"
)

type Capabilities struct {
	Redaction                          RedactionMode
	Receipts, Threads, IdempotentRetry bool
	Membership                         MembershipMode
	MaxContentBytes                    int
}
type ConversationCaps struct{ E2EE bool }
type Message struct {
	Kind, Text  string
	To          []PrincipalID
	Re, Thread  EventID
	Attachments []MediaRef
	Extensions  map[string]json.RawMessage
}
type SendRequest struct {
	Conversation   ConversationID
	Message        Message
	IdempotencyKey string
}
type SendResult struct {
	Outcome Outcome
	Event   EventID
	Refusal string
}
type Event struct {
	ID           EventID
	Conversation ConversationID
	Sender       PrincipalID
	Time         time.Time
	Message      Message
	Redacted     bool
	Raw          []byte
}
type Gap struct {
	Conversation ConversationID
	Reason       string
}
type Invite struct {
	Conversation ConversationID
	Sender       PrincipalID
}
type Batch struct {
	Events  []Event
	Invites []Invite
	Gaps    []Gap
	Next    Cursor
}
type SyncOptions struct{ Limit int }
type Page struct {
	Events []Event
	Next   []byte
}
type Member struct{ ID PrincipalID }
type MediaMeta struct {
	ContentType, Name, SHA256 string
	Size                      int64
}

// MediaRef never reveals its payload through formatting. Bytes explicitly opens it.
type MediaRef struct{ data string }

func NewMediaRef(b []byte) MediaRef           { return MediaRef{string(b)} }
func (r MediaRef) Bytes() []byte              { return []byte(r.data) }
func (r MediaRef) String() string             { return "MediaRef(redacted)" }
func (r MediaRef) GoString() string           { return r.String() }
func (r MediaRef) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, r.String()) }

type Transport interface {
	Self(context.Context) (Principal, error)
	Caps() Capabilities
	ConversationCaps(context.Context, ConversationID) (ConversationCaps, error)
	Addressing() Addressing
	Send(context.Context, SendRequest) (SendResult, error)
	Sync(context.Context, Cursor, SyncOptions) (Batch, error)
	History(context.Context, ConversationID, []byte, int) (Page, error)
	Event(context.Context, ConversationID, EventID) (Event, error)
	Members(context.Context, ConversationID) ([]Member, error)
	Upload(context.Context, io.Reader, MediaMeta) (MediaRef, error)
	Download(context.Context, MediaRef, io.Writer, int64) (MediaMeta, error)
	Close() error
}
type Addressing interface {
	Principal(string) (PrincipalID, error)
	Conversation(context.Context, string) (ConversationID, error)
	Format(PrincipalID) string
}
type Config struct {
	StateDir string
	Settings map[string]string
}
type Factory func(Config) (Transport, error)
type Error struct{ code string }

func (e *Error) Error() string { return "transport: " + e.code }
func NewError(code string) error {
	switch code {
	case "unsupported_by_transport", "content_too_large", "invalid_reference", "invalid_cursor", "unauthenticated", "unavailable", "refused":
	default:
		code = "unavailable"
	}
	return &Error{code}
}
func Code(err error) string {
	if e, ok := err.(*Error); ok {
		return e.code
	}
	return ""
}

var registry = struct {
	sync.Mutex
	factories map[string]Factory
}{factories: map[string]Factory{}}

func Register(name string, f Factory) error {
	registry.Lock()
	defer registry.Unlock()
	if len(name) < 1 || len(name) > 32 || name[0] < 'a' || name[0] > 'z' || f == nil {
		return NewError("invalid_reference")
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return NewError("invalid_reference")
		}
	}
	if _, ok := registry.factories[name]; ok {
		return NewError("refused")
	}
	registry.factories[name] = f
	return nil
}
func Lookup(name string) (Factory, bool) {
	registry.Lock()
	defer registry.Unlock()
	f, ok := registry.factories[name]
	return f, ok
}
func Names() []string {
	registry.Lock()
	defer registry.Unlock()
	var out []string
	for n := range registry.factories {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
