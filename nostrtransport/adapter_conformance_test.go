package nostrtransport

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	seam "github.com/relux-works/a2a-swarm/transport"
)

// NIP-19 encoding of the secp256k1 generator x-coordinate
// 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798.
// This is a valid npub encoding, but the adapter accepts canonical hex only.
const unsupportedNpub = "npub10xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqpkge6d"

func (w *seamWorld) principalReferences() (string, string) {
	return w.b.core.Identity(), unsupportedNpub
}

func (w *seamWorld) conversationReferences() (string, string) {
	return string(w.conv), "{}"
}

// The hooks must be present and their references go through the real parser,
// beside malformed/unsupported neighbors. No parser result is manufactured and
// neither valid nor rejected addressing performs relay I/O.
func TestConformanceReferenceHooks(t *testing.T) {
	f := upstreamFixture(t)
	if f.PrincipalReferences == nil {
		t.Fatal("missing PrincipalReferences hook")
	}
	if f.ConversationReferences == nil {
		t.Fatal("missing ConversationReferences hook")
	}
	ctx := context.Background()
	b, err := f.B.Self(ctx)
	if err != nil {
		t.Fatal(err)
	}
	addr := f.A.Addressing()
	calls := f.WireCalls()
	principal, badPrincipal := f.PrincipalReferences()
	conversation, badConversation := f.ConversationReferences()
	checkValid := func() {
		t.Helper()
		if got, err := addr.Principal(principal); err != nil || got != b.ID {
			t.Fatal("real principal reference changed")
		}
		if got, err := addr.Conversation(ctx, conversation); err != nil || got != f.Conversation {
			t.Fatal("real conversation reference changed")
		}
	}
	checkValid()
	for name, ref := range map[string]string{
		"hook": badPrincipal, "npub": unsupportedNpub,
		"short_hex": principal[:63], "uppercase_hex": strings.ToUpper(principal),
		"malformed_hex": strings.Repeat("g", 64), "invalid_point": strings.Repeat("f", 64),
	} {
		t.Run("principal/"+name, func(t *testing.T) {
			if _, err := addr.Principal(ref); seam.Code(err) != seam.InvalidReference {
				t.Fatal("invalid principal reference accepted")
			}
		})
	}
	foreign, err := json.Marshal(convJSON{P: []string{string(b.ID)}})
	if err != nil {
		t.Fatal(err)
	}
	for name, ref := range map[string]string{
		"hook": badConversation, "malformed": "{", "missing_members": "{}",
		"noncanonical": " " + conversation, "without_self": string(foreign),
	} {
		t.Run("conversation/"+name, func(t *testing.T) {
			if _, err := addr.Conversation(ctx, ref); seam.Code(err) != seam.InvalidReference {
				t.Fatal("invalid conversation reference accepted")
			}
		})
	}
	checkValid()
	if f.WireCalls() != calls {
		t.Fatal("addressing references reached relay")
	}
}
