package nostrtransport

import (
	"fmt"
	"os"
	"strings"

	"github.com/relux-works/a2a-transport-nostr/nostr"
)

// LoadKey loads a BIP-340 identity key from a file that must be a
// regular file with no group/other permissions (0600 or stricter).
// The key is never logged.
func LoadKey(path string) (*nostr.PrivKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("nostrtransport: key file is not a regular file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("nostrtransport: key file mode %04o, want 0600 or stricter", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return nostr.PrivKeyFromHex(strings.TrimSpace(string(raw)))
}

// SaveKey writes a new identity key file (0600) refusing overwrite.
func SaveKey(path string, key *nostr.PrivKey) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(key.Hex() + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
