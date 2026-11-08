package nostr

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Additional event kinds for the transport layer.
const (
	KindFileMessage = 15    // NIP-17 encrypted file message (inside seal/wrap)
	KindDelete      = 5     // NIP-09 deletion request
	KindRelayList   = 10002 // NIP-65
	KindDMRelays    = 10050 // NIP-47/DM relay list
	KindAuth        = 22242 // NIP-42 client authentication
	KindBlossomAuth = 24242 // BUD-02 authorization
)

// RumorOptions shape optional rumor tags.
type RumorOptions struct {
	Subject  string // subject tag (topic)
	ReplyTo  string // parent rumor/event id (NIP-10 reply marker)
	Root     string // thread root id (NIP-10 root marker)
	A2AKind  string // ["a2a-kind", value] tag
	FileTags [][]string
}

// BuildRumor builds an unsigned rumor of the given kind (14 chat or
// 15 file) authored by sender, p-tagging every participant
// (sender included), with its id computed.
func BuildRumor(sender *PrivKey, participants []string, kind int, content string, opts RumorOptions, now int64) (*Event, error) {
	if len(participants) == 0 {
		return nil, fmt.Errorf("rumor: no participants")
	}
	tags := [][]string{}
	for _, p := range participants {
		if err := ParseXOnlyPubKey(p); err != nil {
			return nil, fmt.Errorf("rumor: participant: %w", err)
		}
		tags = append(tags, []string{"p", p})
	}
	if opts.Subject != "" {
		tags = append(tags, []string{"subject", opts.Subject})
	}
	if opts.ReplyTo != "" {
		root := opts.Root
		if root == "" {
			root = opts.ReplyTo
		}
		tags = append(tags, []string{"e", root, "", "root"},
			[]string{"e", opts.ReplyTo, "", "reply"})
	} else if opts.Root != "" {
		tags = append(tags, []string{"e", opts.Root, "", "root"})
	}
	if opts.A2AKind != "" {
		tags = append(tags, []string{"a2a-kind", opts.A2AKind})
	}
	tags = append(tags, opts.FileTags...)
	r := &Event{
		PubKey: sender.PubKeyHex(), CreatedAt: now, Kind: kind,
		Tags: tags, Content: content,
	}
	r.ID = r.ComputeID()
	return r, nil
}

// SealRumor encrypts a rumor to one recipient and signs the seal
// (kind 13) with the sender key.
func SealRumor(sender *PrivKey, rumor *Event, recipientHex string, now int64) (*Event, error) {
	r := *rumor
	r.Sig = ""
	if r.ID == "" {
		r.ID = r.ComputeID()
	}
	rumorJSON, err := json.Marshal(&r)
	if err != nil {
		return nil, err
	}
	ck, err := ConversationKey(sender, recipientHex)
	if err != nil {
		return nil, err
	}
	enc, err := EncryptNIP44(string(rumorJSON), ck, [32]byte{})
	if err != nil {
		return nil, err
	}
	seal := &Event{CreatedAt: jitteredPast(now), Kind: KindSeal,
		Tags: [][]string{}, Content: enc}
	if err := sender.SignEvent(seal); err != nil {
		return nil, err
	}
	return seal, nil
}

// WrapSeal gift-wraps a seal to one recipient under a fresh
// ephemeral key (kind 1059).
func WrapSeal(seal *Event, recipientHex string, now int64) (*Event, error) {
	sealJSON, err := json.Marshal(seal)
	if err != nil {
		return nil, err
	}
	ephemeral, err := GeneratePrivKey()
	if err != nil {
		return nil, err
	}
	ck, err := ConversationKey(ephemeral, recipientHex)
	if err != nil {
		return nil, err
	}
	enc, err := EncryptNIP44(string(sealJSON), ck, [32]byte{})
	if err != nil {
		return nil, err
	}
	wrap := &Event{CreatedAt: jitteredPast(now), Kind: KindGiftWrap,
		Tags: [][]string{{"p", recipientHex}}, Content: enc}
	if err := ephemeral.SignEvent(wrap); err != nil {
		return nil, err
	}
	return wrap, nil
}

// WrapForRecipients seals and wraps one rumor for every recipient
// (NIP-17 groups): one rumor id, one wrap per recipient, in input
// order. Duplicate recipients are wrapped once.
func WrapForRecipients(sender *PrivKey, rumor *Event, recipients []string, now int64) ([]*Event, error) {
	seen := map[string]bool{}
	var wraps []*Event
	for _, r := range recipients {
		if seen[r] {
			continue
		}
		seen[r] = true
		seal, err := SealRumor(sender, rumor, r, now)
		if err != nil {
			return nil, err
		}
		wrap, err := WrapSeal(seal, r, now)
		if err != nil {
			return nil, err
		}
		wraps = append(wraps, wrap)
	}
	if len(wraps) == 0 {
		return nil, fmt.Errorf("wrap: no recipients")
	}
	return wraps, nil
}

// SortedUnique returns the sorted deduplicated copy of a key set.
func SortedUnique(keys []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// BuildRelayListEvent builds a signed kind 10002 (NIP-65): r tags,
// plain = read+write, marker suffix narrows.
func BuildRelayListEvent(key *PrivKey, read, write []string, now int64) (*Event, error) {
	tags := [][]string{}
	both := map[string]bool{}
	for _, u := range read {
		for _, w := range write {
			if u == w {
				both[u] = true
			}
		}
	}
	for _, u := range SortedUnique(read) {
		if both[u] {
			tags = append(tags, []string{"r", u})
		} else {
			tags = append(tags, []string{"r", u, "read"})
		}
	}
	for _, u := range SortedUnique(write) {
		if !both[u] {
			tags = append(tags, []string{"r", u, "write"})
		}
	}
	ev := &Event{CreatedAt: now, Kind: KindRelayList, Tags: tags, Content: ""}
	return ev, key.SignEvent(ev)
}

// ParseRelayList extracts read/write sets from a kind 10002 event.
func ParseRelayList(ev *Event) (read, write []string) {
	for _, t := range ev.Tags {
		if len(t) < 2 || t[0] != "r" {
			continue
		}
		switch {
		case len(t) == 2:
			read = append(read, t[1])
			write = append(write, t[1])
		case t[2] == "read":
			read = append(read, t[1])
		case t[2] == "write":
			write = append(write, t[1])
		}
	}
	return SortedUnique(read), SortedUnique(write)
}

// BuildDMRelaysEvent builds a signed kind 10050 DM relay list.
func BuildDMRelaysEvent(key *PrivKey, urls []string, now int64) (*Event, error) {
	tags := [][]string{}
	for _, u := range SortedUnique(urls) {
		tags = append(tags, []string{"relay", u})
	}
	ev := &Event{CreatedAt: now, Kind: KindDMRelays, Tags: tags, Content: ""}
	return ev, key.SignEvent(ev)
}

// ParseDMRelays extracts DM relay URLs from a kind 10050 event.
func ParseDMRelays(ev *Event) []string {
	var out []string
	for _, t := range ev.Tags {
		if len(t) >= 2 && t[0] == "relay" {
			out = append(out, t[1])
		}
	}
	return SortedUnique(out)
}

// BuildAuthEvent builds a signed NIP-42 kind 22242 AUTH response.
func BuildAuthEvent(key *PrivKey, relayURL, challenge string, now int64) (*Event, error) {
	ev := &Event{CreatedAt: now, Kind: KindAuth, Content: "",
		Tags: [][]string{{"relay", relayURL}, {"challenge", challenge}}}
	return ev, key.SignEvent(ev)
}

// BuildDeleteEvent builds a signed NIP-09 kind 5 deletion request
// for one event id of the given kind.
func BuildDeleteEvent(key *PrivKey, eventID string, kind int, now int64) (*Event, error) {
	ev := &Event{CreatedAt: now, Kind: KindDelete, Content: "",
		Tags: [][]string{{"e", eventID}, {"k", fmt.Sprint(kind)}}}
	return ev, key.SignEvent(ev)
}
