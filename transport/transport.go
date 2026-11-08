// Package transport is the provisional a2a transport interface,
// local copy. It will be replaced by the upstream interface package
// when that seam lands; implementations should keep every
// transport-specific type behind this file so the swap is
// mechanical. Conversation ids and cursors are opaque bytes: the
// core never parses them.
package transport

import "context"

// ConversationID identifies one conversation (opaque).
type ConversationID []byte

// Cursor is an opaque sync position (transport-defined).
type Cursor []byte

// AckStatus says whether a send is known to have been accepted.
type AckStatus int

const (
	// AckUnknown: the outcome is unknown (timeout or non-duplicate
	// rejection). Retry with the same idempotency key is safe.
	AckUnknown AckStatus = iota
	// AckOK: the transport accepted the message.
	AckOK
)

// Capabilities declares what a transport can and cannot promise.
type Capabilities struct {
	E2EE       bool
	Redaction  string // "none" | "best_effort" | "guaranteed"
	Receipts   bool
	Membership string // "sender_side" | "relay_side" | "server_side"
}

// Outgoing is one message to send.
type Outgoing struct {
	Content string
	Kind    string // application message kind (e.g. a2a kind); may be empty
	ReplyTo string // parent message id, may be empty
	Root    string // thread root id, may be empty (defaults to ReplyTo)
	Subject string // per-message subject override; may be empty
}

// FileRef describes an encrypted file attached to a Message.
type FileRef struct {
	URL  string
	Mime string
	// CipherSHA256 is the sha256 of the ciphertext blob; PlainSHA256
	// of the plaintext. DecryptionKey/Nonce are hex (AES-256-GCM).
	CipherSHA256  string
	PlainSHA256   string
	DecryptionKey string
	Nonce         string
}

// Message is one verified inbound message. Sender is always the
// authenticated sender identity; unverifiable traffic never
// surfaces as a Message.
type Message struct {
	ID           string
	Conversation ConversationID
	Sender       string
	Content      string
	CreatedAt    int64
	ReplyTo      string
	Root         string
	Kind         string
	Participants []string
	File         *FileRef
}

// Transport is one messaging backend behind the seam.
type Transport interface {
	// Identity returns the own identity id (transport format).
	Identity() string
	// Send persists then publishes one message. The same
	// idempotency key always maps to the same persisted message
	// bytes; a retry can never create a second, different message.
	Send(ctx context.Context, conv ConversationID, msg Outgoing, idempotencyKey string) (eventID string, ack AckStatus, err error)
	// Sync performs one backlog pass from cursor and returns the
	// next cursor. An empty cursor resumes from persisted state.
	Sync(ctx context.Context, cursor Cursor) ([]Message, Cursor, error)
	// Subscribe delivers the backlog then live messages until ctx
	// ends, returning the latest cursor.
	Subscribe(ctx context.Context, cursor Cursor, handler func(Message)) (Cursor, error)
	// Membership returns the conversation participant ids.
	Membership(ctx context.Context, conv ConversationID) ([]string, error)
	// PutMedia stores a blob and returns its content hash.
	PutMedia(ctx context.Context, data []byte) (hash string, err error)
	// GetMedia fetches a blob by hash and verifies it.
	GetMedia(ctx context.Context, hash string) ([]byte, error)
	// SendFile sends one encrypted file into a conversation.
	SendFile(ctx context.Context, conv ConversationID, mime string, data []byte, idempotencyKey string) (string, AckStatus, error)
	// FetchFile downloads, verifies and decrypts a message's file.
	FetchFile(ctx context.Context, msg Message) ([]byte, error)
	// Redact requests deletion of one own message (best effort
	// where Capabilities says so).
	Redact(ctx context.Context, eventID string) error
	Capabilities() Capabilities
	Close() error
}
