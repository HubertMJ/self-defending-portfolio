package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func get(t *testing.T, s *shop, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func stateOf(t *testing.T, s *shop) State {
	t.Helper()
	rec := get(t, s, http.MethodGet, "/state.json")
	if rec.Code != http.StatusOK {
		t.Fatalf("/state.json: %d %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q", ct)
	}
	var st State
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func newShop(t *testing.T) *shop {
	t.Helper()
	dir := t.TempDir()
	if err := initDocroot(dir); err != nil {
		t.Fatal(err)
	}
	return &shop{docroot: dir}
}

// write replaces a docroot file the way the scenario execs do (echo > .tmp && mv).
func write(t *testing.T, s *shop, name, content string) {
	t.Helper()
	if err := writeAtomic(s.docroot, name, content); err != nil {
		t.Fatal(err)
	}
}

func TestHealthy(t *testing.T) {
	s := newShop(t)
	st := stateOf(t, s)
	if st.Status != "up" || st.Title != "SDP Shop" || st.Banner != "Open for business" {
		t.Fatalf("healthy state: %+v", st)
	}
	if len(st.Checksum) != 16 {
		t.Fatalf("checksum %q is not 16 hex digits", st.Checksum)
	}
	rec := get(t, s, http.MethodGet, "/")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<h1>SDP Shop</h1>") {
		t.Fatalf("index: %d %s", rec.Code, rec.Body)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.HasPrefix(csp, "default-src 'none'") {
		t.Fatalf("index CSP %q", csp)
	}
}

func TestDefaceChangesChecksumAndStatus(t *testing.T) {
	s := newShop(t)
	before := stateOf(t, s)
	write(t, s, "index.html", "<h1>defaced</h1>\n")
	write(t, s, "state.json", `{"status":"defaced","title":"H4CK3D","banner":"Defaced from a shell"}`)
	after := stateOf(t, s)
	if after.Status != "defaced" || after.Title != "H4CK3D" || after.Checksum == before.Checksum {
		t.Fatalf("after deface: %+v (before %+v)", after, before)
	}
}

func TestUnknownStatusIsCompromised(t *testing.T) {
	s := newShop(t)
	write(t, s, "state.json", `{"status":"totally-fine","title":"x","banner":"y"}`)
	if st := stateOf(t, s); st.Status != "compromised" {
		t.Fatalf("status %q", st.Status)
	}
}

func TestClipped(t *testing.T) {
	s := newShop(t)
	long := strings.Repeat("a", 500)
	write(t, s, "state.json", `{"status":"up","title":"`+long+`","banner":"line\none\u0007`+long+`"}`)
	st := stateOf(t, s)
	if len(st.Title) != maxTitle || len([]rune(st.Banner)) != maxBanner || strings.ContainsAny(st.Banner, "\n\a") {
		t.Fatalf("not clipped: title %d, banner %q", len(st.Title), st.Banner)
	}
}

func TestInvalidStateKeepsLastGood(t *testing.T) {
	s := newShop(t)
	write(t, s, "state.json", `{"status":"compromised","title":"SDP Shop","banner":"b"}`)
	stateOf(t, s)
	if err := os.WriteFile(filepath.Join(s.docroot, "state.json"), []byte(`{"status":`), 0o644); err != nil {
		t.Fatal(err)
	}
	if st := stateOf(t, s); st.Status != "compromised" || st.Banner != "b" {
		t.Fatalf("last good not kept: %+v", st)
	}
}

func TestInvalidStateWithoutHistory(t *testing.T) {
	s := &shop{docroot: t.TempDir()}
	if rec := get(t, s, http.MethodGet, "/state.json"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing state: %d", rec.Code)
	}
}

func TestRoutes(t *testing.T) {
	s := newShop(t)
	if rec := get(t, s, http.MethodGet, "/state.json/../etc/shadow"); rec.Code != http.StatusNotFound {
		t.Fatalf("other path: %d", rec.Code)
	}
	if rec := get(t, s, http.MethodPost, "/state.json"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}
	if rec := get(t, s, http.MethodGet, "/.state.json"); rec.Code != http.StatusNotFound {
		t.Fatalf("dotfile: %d", rec.Code)
	}
}

func TestFlagWrittenButNotServed(t *testing.T) {
	s := newShop(t)
	const flag = "SDP{0123456789abcdef}"
	if err := writeFlag(s.docroot, flag); err != nil {
		t.Fatal(err)
	}
	// On disk, 0600, with the flag in it (a trailing newline is fine: `cat` prints it either way).
	info, err := os.Stat(filepath.Join(s.docroot, ".flag"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf(".flag mode %o, want 600", info.Mode().Perm())
	}
	raw, err := os.ReadFile(filepath.Join(s.docroot, ".flag"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != flag {
		t.Fatalf(".flag content %q, want %q", strings.TrimSpace(string(raw)), flag)
	}
	// Never served: there is no route for it, only / and /state.json.
	for _, path := range []string{"/.flag", "/flag", "/state.json/../.flag"} {
		if rec := get(t, s, http.MethodGet, path); rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s: %d, want 404 (the flag must not be served)", path, rec.Code)
		}
	}
	// The flag does not leak into /state.json either.
	if body := get(t, s, http.MethodGet, "/state.json").Body.String(); strings.Contains(body, flag) {
		t.Fatalf("/state.json leaked the flag: %s", body)
	}
}

func TestFlagTruncated(t *testing.T) {
	s := newShop(t)
	if err := writeFlag(s.docroot, strings.Repeat("A", maxFlag+50)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(s.docroot, ".flag"))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.TrimSpace(string(raw))); got != maxFlag {
		t.Fatalf("flag length %d, want capped at %d", got, maxFlag)
	}
}

func TestCheckURL(t *testing.T) {
	cases := map[string]string{
		":8080":        "http://127.0.0.1:8080/state.json",
		"0.0.0.0:9000": "http://127.0.0.1:9000/state.json",
		"[::]:8081":    "http://127.0.0.1:8081/state.json",
		"localhost":    "http://127.0.0.1:8080/state.json",
		"":             "http://127.0.0.1:8080/state.json",
		"host:":        "http://127.0.0.1:8080/state.json",
	}
	for addr, want := range cases {
		if got := checkURL(addr); got != want {
			t.Errorf("checkURL(%q) = %q, want %q", addr, got, want)
		}
	}
}
