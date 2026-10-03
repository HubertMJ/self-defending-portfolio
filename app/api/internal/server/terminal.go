package server

// The terminal endpoints (ADR 0029): the visitor runs catalogue commands into their own run and
// leaves when done. The contract's hard rule holds here - the body carries a command *id*, never
// free text, and the server resolves it against the catalogue before anything reaches the cluster.
// Both are state-changing, so they go through the same-origin check in publicMiddleware, and both
// require the per-run bearer token the attack response handed out (never stored, never in an event).

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/runner"
)

// maxCommandBody caps POST /api/runs/{id}/commands: a one-field JSON object is tiny, so anything
// larger is refused with 413 before it is read.
const maxCommandBody = 256

type commandRequest struct {
	ID string `json:"id"`
}

type commandResponse struct {
	Seq int `json:"seq"`
}

// command runs one catalogue command in a terminal run. 401 wrong/missing token, 404 unknown run or
// command id, 409 the run is not accepting commands or one is already running, 413 body too large,
// 429 over the per-run command budget, 202 accepted with the command's seq.
func (s *Server) command(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > maxCommandBody {
		writeError(w, http.StatusRequestEntityTooLarge, "command body too large")
		return
	}
	token, ok := bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCommandBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "command body too large")
		return
	}
	var req commandRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be {\"id\":\"<command id>\"}")
		return
	}
	seq, err := s.cfg.Runner.Command(r.PathValue("id"), token, req.ID)
	if err != nil {
		writeCommandError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, commandResponse{Seq: seq})
}

// leave ends a terminal run early (DELETE /api/runs/{id} with the token). 401 bad token, 404 unknown
// run, 202 accepted.
func (s *Server) leave(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	if err := s.cfg.Runner.Leave(r.PathValue("id"), token); err != nil {
		writeCommandError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"state": "finishing"})
}

func writeCommandError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, runner.ErrBadToken):
		writeError(w, http.StatusUnauthorized, "wrong or missing token")
	case errors.Is(err, runner.ErrUnknownRun):
		writeError(w, http.StatusNotFound, "unknown run")
	case errors.Is(err, runner.ErrUnknownCmd):
		writeError(w, http.StatusNotFound, "unknown command")
	case errors.Is(err, runner.ErrRunBusy):
		writeError(w, http.StatusConflict, "the run is not ready, is over, or a command is already running")
	case errors.Is(err, runner.ErrTooMany):
		tooMany(w, 0, "too many commands in this run")
	default:
		writeError(w, http.StatusInternalServerError, "command failed")
	}
}

// bearer extracts the token from an `Authorization: Bearer <token>` header.
func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(h[len(prefix):]), true
}
