package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeLab answers every lab endpoint with the same body, prefixed by the endpoint's name.
type fakeLab struct {
	body []byte
	ok   bool
}

func (f fakeLab) Latest(context.Context) ([]byte, bool) { return f.answer("latest") }
func (f fakeLab) VM(context.Context) ([]byte, bool)     { return f.answer("vm") }
func (f fakeLab) Raw(context.Context) ([]byte, bool)    { return f.answer("raw") }

func (f fakeLab) answer(name string) ([]byte, bool) {
	if !f.ok {
		return nil, false
	}
	return []byte(`{"endpoint":"` + name + `","body":` + string(f.body) + `}`), true
}

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
	if string(got) != `{"endpoint":"latest","body":`+string(body)+"}\n" {
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

func TestLabVMAndRaw(t *testing.T) {
	// Each path serves its own reader's JSON as is, with the API's headers; when there is nothing to
	// show, or no lab configured, a JSON 404 with the endpoint's message; any other method 405.
	for _, tc := range []struct {
		path, endpoint, missing string
	}{
		{"/api/lab/vm", "vm", "vm status unavailable"},
		{"/api/lab/raw", "raw", "no run yet"},
	} {
		srv := labServer(t, Config{Lab: fakeLab{body: []byte(`{"x":1}`), ok: true}})
		resp, err := http.Get(srv.URL + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" ||
			resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: status %d, headers %v", tc.path, resp.StatusCode, resp.Header)
		}
		if want := `{"endpoint":"` + tc.endpoint + `","body":{"x":1}}` + "\n"; string(got) != want {
			t.Errorf("%s: body = %q, want %q", tc.path, got, want)
		}

		for name, cfg := range map[string]Config{"empty": {Lab: fakeLab{ok: false}}, "not wired": {}} {
			resp, err := http.Get(labServer(t, cfg).URL + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusNotFound || resp.Header.Get("Content-Type") != "application/json" ||
				resp.Header.Get("Cache-Control") != "no-store" {
				t.Errorf("%s %s: status %d, headers %v", tc.path, name, resp.StatusCode, resp.Header)
			}
			if got := decode[map[string]string](t, resp.Body); got["error"] != tc.missing {
				t.Errorf("%s %s: body = %v, want %q", tc.path, name, got, tc.missing)
			}
			_ = resp.Body.Close()
		}

		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			req, _ := http.NewRequest(method, srv.URL+tc.path, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Content-Type") != "application/json" {
				t.Errorf("%s %s: status %d, type %q, want a JSON 405", method, tc.path, resp.StatusCode, resp.Header.Get("Content-Type"))
			}
		}
	}
}
