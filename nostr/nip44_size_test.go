package nostr

import (
	"strings"
	"testing"
)

// Length prediction matches real encryption at every padding transition and
// its neighbors through the protocol maximum; invalid inputs produce no size.
func TestNIP44PayloadSize(t *testing.T) {
	sizes := map[int]bool{1: true, 65535: true}
	last := 0
	for n := 1; n <= 65535; n++ {
		p := nip44PaddedLen(n)
		if p != last {
			for _, neighbor := range []int{n - 1, n, n + 1} {
				if neighbor >= 1 && neighbor <= 65535 {
					sizes[neighbor] = true
				}
			}
		}
		last = p
	}
	for n := range sizes {
		want, e := NIP44PayloadSize(n)
		if e != nil {
			t.Fatal(e)
		}
		actual, e := EncryptNIP44(strings.Repeat("x", n), [32]byte{1}, [32]byte{2})
		if e != nil || len(actual) != want {
			t.Fatalf("prediction differs at %d: got %d want %d: %v", n, want, len(actual), e)
		}
	}
	for _, n := range []int{-1, 0, 65536, int(^uint(0) >> 1)} {
		if size, e := NIP44PayloadSize(n); e == nil || size != 0 {
			t.Fatalf("invalid NIP44 size accepted: %d", n)
		}
	}
}
