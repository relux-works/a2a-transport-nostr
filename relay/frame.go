package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	tr "github.com/relux-works/a2a-swarm/transport"
)

const (
	// MaxFrameBytes is the unchanged limit for normal, decoded WebSocket messages.
	MaxFrameBytes = 256 << 10
	// DrainFramingAllowance covers the NIP-01 EVENT envelope around a maximum
	// upstream raw event, including the boundary+1 probe. It is not an acceptance
	// allowance: every message above MaxFrameBytes is discarded.
	DrainFramingAllowance = 64 << 10
	MaxDrainBytes         = tr.MaxRawBytes + DrainFramingAllowance
	drainScratchBytes     = 4096
)

var errDrainLimit = errors.New("relay: message exceeds drain ceiling")

// readFrame retains at most the fixed normal-message prefix plus one byte.
// The remainder is discarded through fixed scratch, never buffered as a body.
// MaxDrainBytes applies to a whole WebSocket message, including fragments.
// The reader must be a bounded WebSocket message reader in production.
func readFrame(r io.Reader, frame []byte) ([]byte, bool, error) {
	bounded := &io.LimitedReader{R: r, N: MaxDrainBytes + 1}
	n := 0
	for n < MaxFrameBytes+1 {
		read, err := bounded.Read(frame[n : MaxFrameBytes+1])
		n += read
		if err == io.EOF {
			return frame[:n], n > MaxFrameBytes, nil
		}
		if err != nil {
			return nil, false, err
		}
	}
	var scratch [drainScratchBytes]byte
	total := n
	for {
		n, err := bounded.Read(scratch[:])
		total += n
		if total > MaxDrainBytes {
			return nil, false, errDrainLimit
		}
		if err == io.EOF {
			return frame[:MaxFrameBytes+1], true, nil
		}
		if err != nil {
			return nil, false, err
		}
	}
}

// Decode only the bounded prefix, never the discarded event body. Oversized
// malformed/unattributable messages are drained but not counted as query events.
func discardedSubscription(prefix []byte) string {
	d := json.NewDecoder(bytes.NewReader(prefix))
	first, err := d.Token()
	if err != nil || first != json.Delim('[') {
		return ""
	}
	var kind, id string
	if d.Decode(&kind) != nil || kind != "EVENT" || d.Decode(&id) != nil || id == "" {
		return ""
	}
	body, err := d.Token()
	if err != nil || body != json.Delim('{') {
		return ""
	}
	return id
}
