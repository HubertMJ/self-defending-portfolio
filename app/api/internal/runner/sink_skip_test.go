package runner

import (
	"strings"
	"testing"
)

// After a line over maxLineBytes is dropped, the rest of it - up to its newline, in a later write
// together with the next line - is discarded too, and the next line is published, scrubbed. The
// sink must neither publish the dropped line's tail nor swallow, or skip scrubbing, what follows.
func TestSinkTailAfterDroppedLine(t *testing.T) {
	s, rec := newTestSink(nil)
	s.add("stdout", []byte(strings.Repeat("A", maxLineBytes+500))) // no newline: dropped, skipping
	s.add("stdout", []byte("tail of the long line 10.42.17.203\nnext 10.42.17.204 ok\n"))
	s.finish()
	out := rec.text("stdout")
	if !strings.HasPrefix(out, lineDropped) {
		t.Fatalf("published %q, want the dropped-line marker first", out)
	}
	if strings.Contains(out, "tail of the long line") || strings.Contains(out, "AAAA") {
		t.Fatalf("the dropped line's tail was published: %q", out)
	}
	if !strings.Contains(out, "next ") || !strings.Contains(out, " ok\n") {
		t.Fatalf("the line after the dropped one was lost: %q", out)
	}
	if strings.Contains(out, "10.42.17.") {
		t.Fatalf("an address after the dropped line was published unscrubbed: %q", out)
	}
}
