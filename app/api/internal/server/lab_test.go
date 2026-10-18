package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeLab struct {
	body []byte
	ok   bool
}

func (f fakeLab) Latest(context.Context) ([]byte, bool) { return f.body, f.ok }

func labServer(t *testing.T, cfg Config) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(New(cfg).Public())
	t.Cleanup(srv.Close)
	return srv
}

func TestLabLatest(t *testing.T) {
	body := []byte(`{"schema":1,"sample":false}`)
	srv := labServer(t, Config{Lab: fakeLab{body: body, ok: true}})

	resp, err := http.Get(srv.URL + "/api/lab/latest")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("status %d, type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", resp.Header.Get("Cache-Control"))
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != string(body)+"\n" {
		t.Fatalf("body = %q, want the projected run", got)
	}
}

func TestLabLatestNoRun(t *testing.T) {
	// A lab with no document to show, and no lab configured at all: both answer 404 "no run yet",
	// which the /lab/ page treats as "fall back to the bundled sample".
	for name, cfg := range map[string]Config{
		"empty":     {Lab: fakeLab{ok: false}},
		"not wired": {},
	} {
		srv := labServer(t, cfg)
		resp, err := http.Get(srv.URL + "/api/lab/latest")
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusNotFound || resp.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%s: status %d, type %q", name, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		got := decode[map[string]string](t, resp.Body)
		_ = resp.Body.Close()
		if got["error"] != "no run yet" {
			t.Errorf("%s: body = %v", name, got)
		}
	}
}

func TestLabLatestMethodNotAllowed(t *testing.T) {
	srv := labServer(t, Config{Lab: fakeLab{ok: true, body: []byte("{}")}})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/lab/latest", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", resp.StatusCode)
	}
}
