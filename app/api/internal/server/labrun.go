package server

import (
	"net/http"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/clientip"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/labrun"
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
// cooldown / daily limit / visitor limit, 423 closed (the maintenance window) or 503. No body, no
// cookie, no credential: there is nothing for a cross-site request to borrow, and the public
// middleware already refuses a POST from another origin. On top of the general budget, each address
// block (an IPv6 /48) has 3 POSTs a minute and 2 accepted runs a day, and all visitors together 60
// POSTs a minute; internal/labrun answers a refusal it already knows without any I/O.
func (s *Server) labRunRequest(w http.ResponseWriter, r *http.Request) {
	if s.cfg.LabRun == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	group := clientip.Group(clientip.Key(r))
	if ok, retry := s.cfg.LabRunRequests.Allow(group); !ok {
		tooMany(w, retry, "too many requests")
		return
	}
	if ok, retry := s.cfg.LabRunGlobal.Allow("all"); !ok {
		tooMany(w, retry, "too many requests")
		return
	}
	if ok, next := s.cfg.LabRunQuota.Check(group); !ok {
		writeJSON(w, http.StatusTooManyRequests, labrun.Refusal{Error: "visitor limit", NextAllowedAt: next.UTC().Format(labStamp)})
		return
	}
	q, ref := s.cfg.LabRun.Request(r.Context())
	if ref != nil {
		writeJSON(w, ref.Code, ref)
		return
	}
	s.cfg.LabRunQuota.Add(group)
	writeJSON(w, http.StatusAccepted, q)
}

// labStamp is the time format of the lab endpoints' answers.
const labStamp = "2006-01-02T15:04:05.000Z"

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
		s.logClaimRefused(clientip.Key(r))
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

// logClaimRefused warns about a claim with a missing or wrong token - at most once a minute, with the
// client's rate-limit key only, never the header.
func (s *Server) logClaimRefused(key string) {
	s.claimLogMu.Lock()
	defer s.claimLogMu.Unlock()
	now := s.cfg.Now()
	if !s.claimLogAt.IsZero() && now.Sub(s.claimLogAt) < time.Minute {
		return
	}
	s.claimLogAt = now
	s.cfg.Log.Warn("lab run claim refused: bad token", "client", key)
}
