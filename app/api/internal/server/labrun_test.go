package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/labrun"
)

// fakeLabRun answers with fixed values and counts the claims it saw.
type fakeLabRun struct {
	status  labrun.Status
	refusal *labrun.Refusal
	claimOn bool
	claim   labrun.Claim
	err     error
	claims  int
}

func (f *fakeLabRun) Status(context.Context) labrun.Status { return f.status }
func (f *fakeLabRun) Request(context.Context) (labrun.Queued, *labrun.Refusal) {
	if f.refusal != nil {
		return labrun.Queued{}, f.refusal
	}
	return labrun.Queued{ID: "req-1", State: "queued"}, nil
}
func (f *fakeLabRun) ClaimEnabled() bool            { return f.claimOn }
func (f *fakeLabRun) Authorized(header string) bool { return header == "Bearer good" }
func (f *fakeLabRun) Claim(context.Context) (labrun.Claim, error) {
	f.claims++
	return f.claim, f.err
}

func call(t *testing.T, url, method, auth string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, strings.TrimSpace(string(b))
}

func TestLabRunStatusAndRequest(t *testing.T) {
	f := &fakeLabRun{status: labrun.Status{State: "available", CanStart: true, RunsToday: 2, MaxPerDay: 12}}
	srv := labServer(t, Config{LabRun: f})
	resp, body := call(t, srv.URL+"/api/lab/run", http.MethodGet, "")
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("Cache-Control") != "no-store" ||
		body != `{"state":"available","can_start":true,"runs_today":2,"max_per_day":12}` {
		t.Fatalf("GET: %d %v %s", resp.StatusCode, resp.Header, body)
	}
	if resp, body := call(t, srv.URL+"/api/lab/run", http.MethodPost, ""); resp.StatusCode != http.StatusAccepted || body != `{"id":"req-1","state":"queued"}` {
		t.Fatalf("POST: %d %s", resp.StatusCode, body)
	}
	for _, ref := range []labrun.Refusal{
		{Code: http.StatusConflict, Error: "busy"},
		{Code: http.StatusTooManyRequests, Error: "cooldown", NextAllowedAt: "2026-10-20T12:15:00.000Z"},
		{Code: http.StatusTooManyRequests, Error: "daily limit", NextAllowedAt: "2026-10-21T00:00:00.000Z"},
		{Code: http.StatusLocked, Error: "closed", NextAllowedAt: "2026-10-20T03:50:00.000Z"},
		{Code: http.StatusServiceUnavailable, Error: "unavailable", Reason: "trigger agent not answering"},
	} {
		f.refusal = &ref
		srv := labServer(t, Config{LabRun: f}) // a fresh per-visitor budget for each
		resp, body := call(t, srv.URL+"/api/lab/run", http.MethodPost, "")
		if resp.StatusCode != ref.Code || !strings.Contains(body, `"error":"`+ref.Error+`"`) ||
			(ref.NextAllowedAt != "" && !strings.Contains(body, ref.NextAllowedAt)) {
			t.Errorf("refusal %+v: %d %s", ref, resp.StatusCode, body)
		}
	}
	if resp, _ := call(t, srv.URL+"/api/lab/run", http.MethodPut, ""); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT: %d, want 405", resp.StatusCode)
	}
	// Not wired: 404 on all three.
	plain := labServer(t, Config{})
	for _, c := range []struct{ path, method string }{{"/api/lab/run", "GET"}, {"/api/lab/run", "POST"}, {"/api/lab/run/claim", "POST"}} {
		if resp, _ := call(t, plain.URL+c.path, c.method, "Bearer good"); resp.StatusCode != http.StatusNotFound {
			t.Errorf("not wired %s %s: %d", c.method, c.path, resp.StatusCode)
		}
	}
}

func TestLabRunRequestBudget(t *testing.T) {
	// Each visitor has 3 POSTs a minute on top of the general budget; the 4th is refused before it
	// reaches the state machine.
	f := &fakeLabRun{refusal: &labrun.Refusal{Code: http.StatusConflict, Error: "busy"}}
	srv := labServer(t, Config{LabRun: f})
	for i := 0; i < 3; i++ {
		if resp, _ := call(t, srv.URL+"/api/lab/run", http.MethodPost, ""); resp.StatusCode != http.StatusConflict {
			t.Fatalf("POST %d: %d", i, resp.StatusCode)
		}
	}
	resp, body := call(t, srv.URL+"/api/lab/run", http.MethodPost, "")
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" || body != `{"error":"too many requests"}` {
		t.Fatalf("4th POST: %d %s", resp.StatusCode, body)
	}
	// GET is not counted against it.
	if resp, _ := call(t, srv.URL+"/api/lab/run", http.MethodGet, ""); resp.StatusCode != 200 {
		t.Fatalf("GET after the budget: %d", resp.StatusCode)
	}
}

func TestLabRunClaim(t *testing.T) {
	f := &fakeLabRun{claimOn: true, claim: labrun.Claim{Start: true, ID: "req-1"}}
	srv := labServer(t, Config{LabRun: f})
	for _, auth := range []string{"", "Bearer bad", "good", "Basic Z29vZA=="} {
		resp, body := call(t, srv.URL+"/api/lab/run/claim", http.MethodPost, auth)
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != "Bearer" || body != `{"error":"unauthorized"}` {
			t.Errorf("auth %q: %d %s", auth, resp.StatusCode, body)
		}
	}
	if f.claims != 0 {
		t.Fatalf("unauthorised requests reached Claim %d times", f.claims)
	}
	resp, body := call(t, srv.URL+"/api/lab/run/claim", http.MethodPost, "Bearer good")
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" || body != `{"start":true,"id":"req-1"}` {
		t.Fatalf("claim: %d %v %s", resp.StatusCode, resp.Header, body)
	}
	f.claim = labrun.Claim{}
	if _, body := call(t, srv.URL+"/api/lab/run/claim", http.MethodPost, "Bearer good"); body != `{"start":false}` {
		t.Fatalf("nothing queued: %s", body)
	}
	f.err = errors.New("apiserver down")
	if resp, _ := call(t, srv.URL+"/api/lab/run/claim", http.MethodPost, "Bearer good"); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("store error: %d", resp.StatusCode)
	}
	// Other methods look like an unknown path, not a 405 that would confirm it exists.
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if resp, _ := call(t, srv.URL+"/api/lab/run/claim", m, "Bearer good"); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s claim: %d, want 404", m, resp.StatusCode)
		}
	}
	// No token configured: the path does not exist, whatever is sent.
	f.claimOn = false
	if resp, body := call(t, srv.URL+"/api/lab/run/claim", http.MethodPost, "Bearer good"); resp.StatusCode != http.StatusNotFound || body != `{"error":"not found"}` {
		t.Fatalf("no token: %d %s", resp.StatusCode, body)
	}
}
