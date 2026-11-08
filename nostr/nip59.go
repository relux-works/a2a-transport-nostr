package nostr

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// WrapDM builds a NIP-17 direct message from sender to recipientHex:
// rumor (kind 14, unsigned, id computed) -> seal (kind 13, signed by
// sender, content NIP-44(sender<->recipient)) -> gift wrap (kind 1059,
// signed by a fresh ephemeral key, p-tag recipient). rumorTime is the
// rumor created_at (the canonical message time);
// seal/wrap timestamps are jittered into the past per NIP-59.
func WrapDM(sender *PrivKey, recipientHex, content string, extraTags [][]string, rumorTime int64) (*Event, *Event, error) {
	if err := ParseXOnlyPubKey(recipientHex); err != nil {
		return nil, nil, fmt.Errorf("recipient: %w", err)
	}
	tags := make([][]string, 0, len(extraTags)+1)
	tags = append(tags, extraTags...)
	tags = append(tags, []string{"p", recipientHex})
	rumor := &Event{
		PubKey:    sender.PubKeyHex(),
		CreatedAt: rumorTime,
		Kind:      KindRumor,
		Tags:      tags,
		Content:   content,
	}
	rumor.ID = rumor.ComputeID()
	wrap, err := GiftWrap(rumor, sender, recipientHex, rumorTime)
	return wrap, rumor, err
}

// GiftWrap seals and wraps an already-built rumor (used in tests to
// construct adversarial rumors). The rumor signature is cleared; its
// pubkey is taken as-is so tests can build mismatched rumors on
// purpose. Production callers use WrapDM.
func GiftWrap(rumor *Event, sealSigner *PrivKey, recipientHex string, now int64) (*Event, error) {
	seal, err := SealRumor(sealSigner, rumor, recipientHex, now)
	if err != nil {
		return nil, err
	}
	return WrapSeal(seal, recipientHex, now)
}

// UnwrappedDM is the result of strict unwrapping: the rumor and the
// authenticated sender (the seal pubkey, never the gift-wrap key).
type UnwrappedDM struct {
	Rumor      *Event
	Seal       *Event
	SenderHex  string // == Seal.PubKey == Rumor.PubKey (enforced)
	WrapperHex string // gift-wrap pubkey (unauthenticated, for logging shape only)
}

// UnwrapDM strictly unwraps a gift wrap addressed to recipient, in the
// strict layer order. Each failure names its layer so the caller
// can record a precise refusal reason:
//
//  1. kind must be 1059; p-tag must name recipient; wrap id+sig verify.
//  2. NIP-44 decrypt (recipient <-> wrap key) -> seal JSON parses.
//  3. seal kind must be 13; seal id+sig verify; seal must have no tags.
//  4. NIP-44 decrypt (recipient <-> seal key) -> rumor JSON parses.
//  5. rumor pubkey must equal seal pubkey; rumor id must recompute;
//     rumor must carry no signature.
func UnwrapDM(wrap *Event, recipient *PrivKey) (*UnwrappedDM, error) {
	if wrap.Kind != KindGiftWrap {
		return nil, fmt.Errorf("wrap: kind %d, want %d", wrap.Kind, KindGiftWrap)
	}
	if p, ok := wrap.TagFirst("p"); !ok || p != recipient.PubKeyHex() {
		return nil, fmt.Errorf("wrap: p tag does not name recipient")
	}
	if err := VerifySignature(wrap); err != nil {
		return nil, fmt.Errorf("wrap: %w", err)
	}
	ckWrap, err := ConversationKey(recipient, wrap.PubKey)
	if err != nil {
		return nil, fmt.Errorf("wrap key: %w", err)
	}
	sealJSON, err := DecryptNIP44(wrap.Content, ckWrap)
	if err != nil {
		return nil, fmt.Errorf("wrap decrypt: %w", err)
	}
	seal, err := ParseEvent([]byte(sealJSON))
	if err != nil {
		return nil, fmt.Errorf("seal parse: %w", err)
	}
	if seal.Kind != KindSeal {
		return nil, fmt.Errorf("seal: kind %d, want %d", seal.Kind, KindSeal)
	}
	if len(seal.Tags) != 0 {
		return nil, fmt.Errorf("seal: tags must be empty")
	}
	if err := VerifySignature(seal); err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	ckSeal, err := ConversationKey(recipient, seal.PubKey)
	if err != nil {
		return nil, fmt.Errorf("seal key: %w", err)
	}
	rumorJSON, err := DecryptNIP44(seal.Content, ckSeal)
	if err != nil {
		return nil, fmt.Errorf("seal decrypt: %w", err)
	}
	rumor, err := ParseEvent([]byte(rumorJSON))
	if err != nil {
		return nil, fmt.Errorf("rumor parse: %w", err)
	}
	if rumor.Kind != KindRumor && rumor.Kind != KindFileMessage {
		return nil, fmt.Errorf("rumor: kind %d, want %d or %d", rumor.Kind, KindRumor, KindFileMessage)
	}
	if rumor.PubKey != seal.PubKey {
		return nil, fmt.Errorf("rumor: pubkey does not match seal pubkey")
	}
	if rumor.Sig != "" {
		return nil, fmt.Errorf("rumor: must be unsigned")
	}
	if !rumor.CheckID() {
		return nil, fmt.Errorf("rumor: id mismatch")
	}
	return &UnwrappedDM{Rumor: rumor, Seal: seal, SenderHex: seal.PubKey, WrapperHex: wrap.PubKey}, nil
}

// jitteredPast offsets now into the past per NIP-59, clamped at 0:
// created_at must never be negative.
func jitteredPast(now int64) int64 {
	if t := now - jitterSeconds(); t > 0 {
		return t
	}
	return 0
}

// jitterSeconds returns a uniform offset in [0, 2 days) from crypto/rand.
func jitterSeconds() int64 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int64(binary.BigEndian.Uint32(b[:]) % 172800)
}
