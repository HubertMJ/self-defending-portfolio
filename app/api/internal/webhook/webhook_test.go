package webhook

import (
	"strings"
	"sync"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func TestParseFalco(t *testing.T) {
	body := `{"uuid":"x","output":"` + strings.Repeat("a", 400) + `","priority":"Notice","rule":"Terminal shell in container",
	"time":"2026-10-01T11:59:58.123456789Z","source":"syscall","hostname":"node",
	"output_fields":{"k8s.ns.name":"sandbox","k8s.pod.name":"shell-in-container-abc","proc.name":"sh","evt.time":1}}`
	ev, err := ParseFalco([]byte(body), now)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Rule != "Terminal shell in container" || ev.Priority != "Notice" || ev.Namespace != "sandbox" || ev.Pod != "shell-in-container-abc" {
		t.Fatalf("%+v", ev)
	}
	if n := len([]rune(ev.Output)); n != MaxOutput {
		t.Fatalf("output is %d runes, want %d", n, MaxOutput)
	}
	if ev.At != time.Date(2026, 10, 1, 11, 59, 58, 123456789, time.UTC) {
		t.Fatalf("at = %v", ev.At)
	}
}

func TestParseFalcoNullFields(t *testing.T) {
	ev, err := ParseFalco([]byte(`{"rule":"r","output_fields":{"k8s.ns.name":null}}`), now)
	if err != nil || ev.Namespace != "" || ev.Pod != "" || ev.At != now {
		t.Fatalf("%+v %v", ev, err)
	}
	if _, err := ParseFalco([]byte(`not json`), now); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestParseTalon(t *testing.T) {
	cases := []struct{ body, action, pod, ns, status string }{
		{`{"objects":{"Pod":"p1","Namespace":"sandbox"},"action":"Terminate Pod","actionner":"kubernetes:terminate","status":"success","rule":"Kill terminal shell in sandbox"}`,
			"Terminate Pod", "p1", "sandbox", "success"},
		{`{"objects":{"pod":"p2","namespace":"sandbox"},"actionner":"kubernetes:label","status":"failure","error":"x"}`,
			"kubernetes:label", "p2", "sandbox", "failure"},
		{`{"Status":"success"}`, "", "", "", "success"},
	}
	for _, c := range cases {
		ev, err := ParseTalon([]byte(c.body), now)
		if err != nil {
			t.Fatal(err)
		}
		if ev.Action != c.action || ev.Pod != c.pod || ev.Namespace != c.ns || ev.Status != c.status || ev.At != now {
			t.Errorf("%s -> %+v", c.body, ev)
		}
	}
}

func TestTruncateKeepsRunes(t *testing.T) {
	s := strings.Repeat("ż", 10)
	if got := Truncate(s, 5); got != "żżżż…" {
		t.Fatalf("%q", got)
	}
	if Truncate("short", 300) != "short" {
		t.Fatal("short string changed")
	}
}

func TestWindow(t *testing.T) {
	var mu sync.Mutex
	clk := now
	w := NewDayWindow(func() time.Time { mu.Lock(); defer mu.Unlock(); return clk })
	advance := func(d time.Duration) { mu.Lock(); clk = clk.Add(d); mu.Unlock() }
	w.Add()
	w.Add()
	advance(12 * time.Hour)
	w.Add()
	if w.Count() != 3 {
		t.Fatalf("count = %d", w.Count())
	}
	advance(12*time.Hour + time.Minute)
	if w.Count() != 1 {
		t.Fatalf("after 24h: count = %d, want 1", w.Count())
	}
	advance(48 * time.Hour)
	if w.Count() != 0 {
		t.Fatalf("after 72h: count = %d", w.Count())
	}
	// A slot reused after a full lap starts from zero.
	w.Add()
	if w.Count() != 1 {
		t.Fatalf("reused slot: %d", w.Count())
	}
}
