package flagmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

func TestSumIsHMACSHA256(t *testing.T) {
	k := New()
	m := hmac.New(sha256.New, k.k)
	m.Write([]byte("sdp-0123456789abcdef"))
	if !bytes.Equal(k.Sum("sdp-0123456789abcdef"), m.Sum(nil)) {
		t.Fatal("Sum is not HMAC-SHA256 over the label")
	}
}

func TestKeysDiffer(t *testing.T) {
	a, b := New(), New()
	if bytes.Equal(a.Sum("sdp-0123456789abcdef"), b.Sum("sdp-0123456789abcdef")) {
		t.Fatal("two processes' keys gave the same MAC")
	}
	if bytes.Equal(a.Sum("sdp-0123456789abcdef"), a.Sum("sdp-0123456789abcdee")) {
		t.Fatal("different labels gave the same MAC")
	}
}
