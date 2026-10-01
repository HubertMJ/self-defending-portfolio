package webhook

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func TestParseFalco(t *testing.T) {
	body := `{"uuid":"x","output":"` + strings.Repeat("a", 1100) + `","priority":"Notice","rule":"Terminal shell in container",
	"time":"2026-10-01T11:59:58.123456789Z","source":"syscall","hostname":"node",
	"output_fields":{"k8s.ns.name":"sandbox","k8s.pod.name":"shell-in-container-abc","proc.name":"sh","evt.time":1,
	"user.uid":10001,"container.id":"0123456789abcdef0123","proc.cmdline":"sh -c id","k8s.pod.uid":"u","hostname":"node1",
	"proc.pname":null,"fd.name":"` + strings.Repeat("f", 300) + `"}}`
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
	if ev.At != time.Date(2026, 10, 1, 11, 59, 58, 123456789, time.UTC) || ev.APIReceivedAt != now {
		t.Fatalf("at = %v, api_received_at = %v", ev.At, ev.APIReceivedAt)
	}
	// Allow-listed fields only; container.id cut to 12; null dropped; long values capped.
	want := map[string]any{"k8s.ns.name": "sandbox", "k8s.pod.name": "shell-in-container-abc", "proc.name": "sh",
		"user.uid": float64(10001), "container.id": "0123456789ab", "proc.cmdline": "sh -c id"}
	for k, v := range want {
		if ev.Fields[k] != v {
			t.Errorf("fields[%s] = %v, want %v", k, ev.Fields[k], v)
		}
	}
	if n := len([]rune(ev.Fields["fd.name"].(string))); n != MaxFieldValue {
		t.Errorf("fd.name is %d runes", n)
	}
	for _, k := range []string{"evt.time", "k8s.pod.uid", "hostname", "proc.pname"} {
		if _, ok := ev.Fields[k]; ok {
			t.Errorf("field %s published", k)
		}
	}
}

func TestFalcoEventJSONHasEmptyFields(t *testing.T) {
	ev, _ := ParseFalco([]byte(`{"rule":"r"}`), now)
	b, _ := json.Marshal(ev)
	if !strings.Contains(string(b), `"fields":{}`) || !strings.Contains(string(b), `"api_received_at":"2026-10-01T12:00:00Z"`) {
		t.Fatalf("%s", b)
	}
}

func TestScrub(t *testing.T) {
	cases := map[string]string{
		"wget http://127.0.0.1:9/ failed":                         "wget http://127.0.0.1:9/ failed",
		"Delete https://10.43.0.1:443/api/v1/pods/x: dial tcp":    "Delete [url] dial tcp",
		"connect 10.42.0.17:8080 refused":                         "connect [ip]:8080 refused",
		"lookup portfolio-api.portfolio-api.svc.cluster.local ok": "lookup [service] ok",
		"plain text stays":                                        "plain text stays",
	}
	for in, want := range cases {
		if got := Scrub(in); got != want {
			t.Errorf("Scrub(%q) = %q, want %q", in, got, want)
		}
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
	cases := []struct{ body, action, actionner, pod, ns, status, output string }{
		{`{"objects":{"Pod":"p1","Namespace":"sandbox"},"action":"Terminate Pod","actionner":"kubernetes:terminate","status":"success","rule":"Kill terminal shell in sandbox",
		  "event":"the whole falco alert","result":"the pod 'p1' in the namespace 'sandbox' has been terminated"}`,
			"Terminate Pod", "kubernetes:terminate", "p1", "sandbox", "success", "the pod 'p1' in the namespace 'sandbox' has been terminated"},
		{`{"objects":{"pod":"p2","namespace":"sandbox"},"actionner":"kubernetes:label","status":"failure","error":"Patch https://10.43.0.1:443/x: timeout"}`,
			"kubernetes:label", "kubernetes:label", "p2", "sandbox", "failure", "Patch [url] timeout"},
		{`{"Status":"success","Output":"` + strings.Repeat("o", 400) + `"}`, "", "", "", "", "success", strings.Repeat("o", 299) + "…"},
	}
	for _, c := range cases {
		ev, err := ParseTalon([]byte(c.body), now)
		if err != nil {
			t.Fatal(err)
		}
		if ev.Action != c.action || ev.Actionner != c.actionner || ev.Pod != c.pod || ev.Namespace != c.ns ||
			ev.Status != c.status || ev.Output != c.output || ev.At != now || ev.APIReceivedAt != now {
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
