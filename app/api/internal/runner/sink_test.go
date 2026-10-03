package runner

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// sinkRec collects what a cmdSink publishes, in order.
type sinkRec struct {
	chunks  []string
	streams []string
}

func newTestSink(rn *run) (*cmdSink, *sinkRec) {
	rec := &sinkRec{}
	if rn == nil {
		rn = &run{}
	}
	s := &cmdSink{rn: rn, publish: func(stream, chunk string) {
		rec.streams = append(rec.streams, stream)
		rec.chunks = append(rec.chunks, chunk)
	}}
	return s, rec
}

func (r *sinkRec) text(stream string) string {
	var b strings.Builder
	for i, c := range r.chunks {
		if r.streams[i] == stream {
			b.WriteString(c)
		}
	}
	return b.String()
}

func (r *sinkRec) bytes() int {
	n := 0
	for _, c := range r.chunks {
		n += len(c)
	}
	return n
}

// writeIn feeds p to the sink in writes of the given size.
func writeIn(s *cmdSink, stream string, p []byte, size int) {
	for len(p) > 0 {
		n := size
		if n > len(p) {
			n = len(p)
		}
		s.add(stream, p[:n])
		p = p[n:]
	}
}

// within fails the test if f does not return in time: the sink must make progress on every input.
func within(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %s", what, d)
	}
}

// A run of UTF-8 continuation bytes has no rune boundary to cut at. The sink must neither buffer it
// without bound nor spin on it: it is one over-long line, dropped whole.
func TestSinkContinuationBytesTerminate(t *testing.T) {
	for _, size := range []int{1, 7, 1024, 4096, 1 << 20} {
		s, rec := newTestSink(nil)
		within(t, 5*time.Second, "add+finish", func() {
			writeIn(s, "stdout", bytes.Repeat([]byte{0x80}, 2<<20), size)
			if !s.finish() {
				t.Errorf("write size %d: an over-long line was dropped, truncated must be set", size)
			}
		})
		if got := rec.text("stdout"); got != lineDropped {
			t.Errorf("write size %d: published %q, want only the marker", size, got)
		}
		if st := s.streams["stdout"]; st != nil && (len(st.pending) > maxLineBytes || len(st.out) > 0) {
			t.Errorf("write size %d: sink kept %d pending and %d queued bytes", size, len(st.pending), len(st.out))
		}
	}
}

// Whatever the write sizes and the content, no event carries more than commandChunkBytes and every
// chunk is valid UTF-8 - including text the scrubber makes longer than what it replaced.
func TestSinkChunkBound(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	parts := []string{"a.svc ", "x", "é", "日本", "\n", "\n", " 10.42.17.203 ", "::2 ", "https://h.example/p ",
		"\x00", "\x1b[31m", "\r", "\x80", strings.Repeat("y", 300), "kube-dns.kube-system.svc.cluster.local\n"}
	for i := 0; i < 300; i++ {
		var in bytes.Buffer
		for in.Len() < 3000 {
			in.WriteString(parts[rng.Intn(len(parts))])
		}
		s, rec := newTestSink(nil)
		p := in.Bytes()
		for len(p) > 0 {
			n := 1 + rng.Intn(40000)
			if n > len(p) {
				n = len(p)
			}
			stream := "stdout"
			if rng.Intn(4) == 0 {
				stream = "stderr"
			}
			s.add(stream, p[:n])
			p = p[n:]
		}
		s.finish()
		for _, c := range rec.chunks {
			if len(c) > commandChunkBytes {
				t.Fatalf("iteration %d: chunk of %d bytes", i, len(c))
			}
			if !utf8.ValidString(c) {
				t.Fatalf("iteration %d: chunk is not valid UTF-8: %q", i, c)
			}
			if c == "" {
				t.Fatalf("iteration %d: empty chunk published", i)
			}
		}
	}
}

// The invariant of cmdSink: an address, URL or service name printed on one line is never published,
// wherever the pod cuts its writes, however long the line before it is, and whatever bytes the
// sanitiser removes around it. The fillers and lengths are the ones that got a token past the
// earlier, cut-then-scrub sink: bytes the sanitiser drops (so the published half stays small) and
// prefixes that put the token on the chunk bound and on the line bound.
func TestSinkTokenNeverPublished(t *testing.T) {
	tokens := []string{
		"10.42.17.203",
		"https://kube-api.example.internal/x",
		"kube-dns.kube-system.svc",
		"kube-dns.kube-system.svc.cluster.local",
		"fd00:10:42::1f",
	}
	fillers := []string{"a", "\x00", "\x80", "\r"}
	// Around the event size, the line bound, and the old 8 KiB cut.
	bases := []int{0, commandChunkBytes, maxLineBytes, 8 << 10}
	check := func(stream, tok, fill string, pre int) {
		prefix := strings.Repeat(fill, pre) + " "
		for cut := 0; cut <= len(tok); cut++ {
			s, rec := newTestSink(nil)
			s.add(stream, []byte(prefix+tok[:cut]))
			s.add(stream, []byte(tok[cut:]+" tail\n"))
			s.finish()
			if got := rec.text(stream); strings.Contains(got, tok) {
				t.Fatalf("%s: %q published after %d bytes of %q, write cut at %d: %q",
					stream, tok, pre, fill, cut, tail(got, 120))
			}
		}
	}
	for _, tok := range tokens {
		for _, fill := range fillers {
			for _, base := range bases {
				// Every offset at which the token straddles the bound, and a little either side.
				for pre := base - len(tok) - 3; pre <= base+2; pre++ {
					if pre >= 0 {
						check("stdout", tok, fill, pre)
					}
				}
			}
		}
		// stderr takes the same path; one bound is enough to show it.
		for pre := maxLineBytes - len(tok) - 3; pre <= maxLineBytes+2; pre++ {
			check("stderr", tok, "\x00", pre)
		}
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// The same property under random write sizes: the line is fed in arbitrary pieces.
func TestSinkTokenNeverPublishedRandomWrites(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	tokens := []string{"10.42.17.203", "https://kube-api.example.internal/x", "kube-dns.kube-system.svc", "fd00:10:42::1f"}
	fillers := []string{"a", "\x00", "\x80", "\r"}
	for i := 0; i < 2000; i++ {
		tok := tokens[rng.Intn(len(tokens))]
		fill := fillers[rng.Intn(len(fillers))]
		line := strings.Repeat(fill, rng.Intn(3*maxLineBytes)) + " " + tok + " " + strings.Repeat(fill, rng.Intn(64)) + "\n"
		s, rec := newTestSink(nil)
		p := []byte(line)
		for len(p) > 0 {
			n := 1 + rng.Intn(1+len(p))
			if n > len(p) {
				n = len(p)
			}
			s.add("stdout", p[:n])
			p = p[n:]
		}
		s.finish()
		if got := rec.text("stdout"); strings.Contains(got, tok) {
			t.Fatalf("iteration %d: %q published: %q", i, tok, tail(got, 120))
		}
	}
}

// A line longer than maxLineBytes is replaced by the marker; the lines around it are untouched.
func TestSinkLongLineDropped(t *testing.T) {
	s, rec := newTestSink(nil)
	in := "before\n" + strings.Repeat("x", maxLineBytes+1) + "\nafter\n"
	writeIn(s, "stdout", []byte(in), 100)
	if !s.finish() {
		t.Error("a dropped line must report truncated")
	}
	if got, want := rec.text("stdout"), "before\n"+lineDropped+"after\n"; got != want {
		t.Errorf("published %q, want %q", got, want)
	}
	// Exactly at the bound the line is kept.
	s, rec = newTestSink(nil)
	line := strings.Repeat("x", maxLineBytes-1) + "\n"
	s.add("stdout", []byte(line))
	if s.finish() {
		t.Error("a line of exactly maxLineBytes is not truncated")
	}
	if got := rec.text("stdout"); got != line {
		t.Errorf("a line of maxLineBytes: published %d bytes, want %d", len(got), len(line))
	}
}

// A rune split across two writes is put together again, and the last line needs no newline.
func TestSinkRuneAcrossWritesAndLastLine(t *testing.T) {
	s, rec := newTestSink(nil)
	s.add("stdout", []byte("caf\xc3"))
	s.add("stdout", []byte("\xa9\nno newline"))
	if s.finish() {
		t.Error("nothing was dropped")
	}
	if got, want := rec.text("stdout"), "café\nno newline"; got != want {
		t.Errorf("published %q, want %q", got, want)
	}
	// A rune cut off by the end of the stream is dropped, not published as garbage.
	s, rec = newTestSink(nil)
	s.add("stdout", []byte("x\xc3"))
	s.finish()
	if got := rec.text("stdout"); got != "x" {
		t.Errorf("published %q, want %q", got, "x")
	}
}

// One write of many short lines is a few events, not one per line.
func TestSinkBatchesLines(t *testing.T) {
	s, rec := newTestSink(nil)
	s.add("stdout", []byte(strings.Repeat("ab\n", 1000)))
	s.finish()
	if len(rec.chunks) > 3 {
		t.Errorf("3000 bytes in one write became %d events, want at most 3", len(rec.chunks))
	}
	if got := rec.bytes(); got != 3000 {
		t.Errorf("published %d bytes, want 3000", got)
	}
}

// The per-command caps: bytes (counted after scrubbing) and events.
func TestSinkCommandCaps(t *testing.T) {
	s, rec := newTestSink(nil)
	writeIn(s, "stdout", []byte(strings.Repeat("0123456789abcde\n", 1000)), 4000)
	if !s.finish() {
		t.Error("output over the cap must report truncated")
	}
	if got := rec.bytes(); got != commandOutBytes {
		t.Errorf("published %d bytes, want exactly the cap %d", got, commandOutBytes)
	}

	// One line per write: the event cap ends it long before the byte cap.
	s, rec = newTestSink(nil)
	for i := 0; i < 1000; i++ {
		s.add("stdout", []byte("x\n"))
	}
	if !s.finish() {
		t.Error("output over the event cap must report truncated")
	}
	if len(rec.chunks) != commandOutEvents {
		t.Errorf("published %d events, want exactly the cap %d", len(rec.chunks), commandOutEvents)
	}
}

// The per-run caps hold across the commands of one run.
func TestSinkRunCaps(t *testing.T) {
	rn := &run{}
	total, events := 0, 0
	for c := 0; c < MaxCommandsPerRun; c++ {
		s, rec := newTestSink(rn)
		// Five lines of 1001 bytes: more than one command may publish, each line within the bound.
		writeIn(s, "stdout", []byte(strings.Repeat(strings.Repeat("é", 500)+"\n", 5)), 700)
		s.finish()
		total += rec.bytes()
		events += len(rec.chunks)
	}
	if total > runOutBytes {
		t.Errorf("run published %d bytes, cap %d", total, runOutBytes)
	}
	if total < runOutBytes-commandChunkBytes {
		t.Errorf("run published only %d bytes of its %d budget", total, runOutBytes)
	}

	rn = &run{}
	events = 0
	for c := 0; c < MaxCommandsPerRun; c++ {
		s, rec := newTestSink(rn)
		for i := 0; i < commandOutEvents; i++ {
			s.add("stdout", []byte("x\n"))
		}
		s.finish()
		events += len(rec.chunks)
	}
	if events != runOutEvents {
		t.Errorf("run published %d output events, want exactly the cap %d", events, runOutEvents)
	}
}

// After finish nothing is published, and stderr is handled like stdout.
func TestSinkLateWriteAndStderr(t *testing.T) {
	s, rec := newTestSink(nil)
	s.add("stderr", []byte("wget: can't connect to 10.42.17.203\n"))
	s.finish()
	if got, want := rec.text("stderr"), "wget: can't connect to [ip]\n"; got != want {
		t.Errorf("stderr published %q, want %q", got, want)
	}
	n := len(rec.chunks)
	s.add("stdout", []byte("late\n"))
	s.add("stderr", []byte("late\n"))
	if len(rec.chunks) != n {
		t.Errorf("a write after finish was published: %q", rec.chunks[n:])
	}
}
