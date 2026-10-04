// Package flagmac holds the per-process key the dns-exfil flag match uses (ADR 0036, "Flag match").
//
// The runner MACs a terminal run's flag label (`sdp-<16 hex>`) with it at the run's start and hands
// only the MAC on; the incident tracker MACs the first label of a DNS query the SIEM saw and compares
// the two. So the flag itself never leaves the runner, and the tracker never holds a value from which
// the flag could be read back. The key is 32 random bytes made at process start and never stored:
// a restart makes every earlier MAC meaningless, which the page shows as "flag match unavailable".
package flagmac

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

// Key is safe for concurrent use: it is never changed after New.
type Key struct{ k []byte }

// New makes a fresh random key.
func New() *Key {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err) // crypto/rand does not fail on Linux
	}
	return &Key{k: k}
}

// Sum is HMAC-SHA256(key, label).
func (k *Key) Sum(label string) []byte {
	m := hmac.New(sha256.New, k.k)
	_, _ = m.Write([]byte(label))
	return m.Sum(nil)
}
