package server

import (
	"net/http"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/clientip"
)

// labRunStatus answers whether a visitor may start an isolated-VM run now, and if not, why and from
// when (ADR 0034 amendment 2026-10-20 (b)). internal/labrun caches it for 2 s.
func (s *Server) labRunStatus(w http.ResponseWriter, r *http.Request) {
	if s.cfg.LabRun == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, s.cfg.LabRun.Status(r.Context()))
}

// labRunRequest queues a visitor's run: 202 when the rules allow one now, else 409 busy, 429
// cooldown / daily limit, 423 closed (the maintenance window) or 503. No body, no cookie, no
// credential: there is nothing for a cross-site request to borrow, and the public middleware already
// refuses a POST from another origin. Each visitor has 3 requests a minute on top of the general
// budget, so hammering the button costs one read each, not a run.
func (s *Server) labRunRequest(w http.ResponseWriter, r *http.Request) {
	if s.cfg.LabRun == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if ok, retry := s.cfg.LabRunRequests.Allow(clientip.Key(r)); !ok {
		tooMany(w, retry, "too many requests")
		return
	}
	q, ref := s.cfg.LabRun.Request(r.Context())
	if ref != nil {
		writeJSON(w, ref.Code, ref)
		return
	}
	writeJSON(w, http.StatusAccepted, q)
}

// labRunClaim is the trigger agent's poll: with the bearer token from the mounted Secret it gets
// {"start":true,"id"} exactly once for a queued request, else {"start":false}. The agent on the
// hypervisor only ever connects out; nothing reaches it. 404 while no token is configured (the path
// does not exist then), 401 on a missing or wrong token.
func (s *Server) labRunClaim(w http.ResponseWriter, r *http.Request) {
	if s.cfg.LabRun == nil || !s.cfg.LabRun.ClaimEnabled() {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if !s.cfg.LabRun.Authorized(r.Header.Get("Authorization")) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	c, err := s.cfg.LabRun.Claim(r.Context())
	if err != nil {
		s.cfg.Log.Warn("lab run claim failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	writeJSON(w, http.StatusOK, c)
}
