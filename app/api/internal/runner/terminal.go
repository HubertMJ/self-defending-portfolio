package runner

// The attacker's terminal (ADR 0029). A scenario with `interactive: true` is not run by a single
// scripted exec: the pod is created and kept alive, and the visitor sends catalogue command *ids*
// (never free text - the contract's hard rule), one at a time, which the runner execs into the
// `target` container and streams back as `command` events. The run ends when the pod is killed by
// Talon (a detected/terminate command), when the visitor leaves, after the idle timeout without a
// command, or at the scenario deadline.
//
// Output is untrusted (it is whatever runs in the attacked pod printed): it is forced to valid
// UTF-8, stripped of every control character except newline and tab (so no ANSI escapes) and of
// invisible format characters, then run through the ADR 0021 scrubber (URLs, IPs and in-cluster
// service names, loopback excepted), and capped at 4 KiB per command and 32 KiB per run. The run's
// flag is not special-cased: it is this run's own secret and is meant to be seen by the visitor who
// read it.

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/webhook"
)

// Command event states.
const (
	CommandStarted = "started"
	CommandOutput  = "output"
	CommandExited  = "exited"
	CommandKilled  = "killed"
)

// Caps on terminal command output and on how many commands a run accepts (ADR 0029).
const (
	MaxCommandsPerRun = 30
	commandChunkBytes = 1024     // one `output` event carries at most this much text
	commandOutBytes   = 4 << 10  // per command
	runOutBytes       = 32 << 10 // per run
)

// Errors Command and Leave return; the server maps them to status codes.
var (
	ErrUnknownRun = errors.New("unknown run")
	ErrBadToken   = errors.New("wrong or missing token")
	ErrUnknownCmd = errors.New("unknown command")
	ErrRunBusy    = errors.New("the run is not ready, is over, or a command is already running")
	ErrTooMany    = errors.New("too many commands in this run")
)

// CommandEvent is the public `event: command` payload (ADR 0029). ExitCode is set only for
// `exited`; Achieved, Chunk, Stream and Truncated only where they apply.
type CommandEvent struct {
	RunID     string    `json:"run_id"`
	Seq       int       `json:"seq"`
	ID        string    `json:"id"`
	State     string    `json:"state"`
	At        time.Time `json:"at"`
	Stream    string    `json:"stream,omitempty"`
	Chunk     string    `json:"chunk,omitempty"`
	ExitCode  *int      `json:"exit_code,omitempty"`
	Achieved  bool      `json:"achieved,omitempty"`
	Truncated bool      `json:"truncated,omitempty"`
	Arm       string    `json:"arm,omitempty"`
}

// Command executes catalogue command `commandID` in the terminal run `runID`. It returns the
// command's sequence number, or one of the sentinel errors above (unknown run or command, wrong
// token, busy/over, too many). The token is compared in constant time.
func (r *Runner) Command(runID, token, commandID string) (int, error) {
	rn := r.lookupID(runID)
	if rn == nil || !rn.terminal {
		return 0, ErrUnknownRun
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(rn.token)) != 1 {
		return 0, ErrBadToken
	}
	cmd, ok := rn.sc.CommandByID(commandID)
	if !ok {
		return 0, ErrUnknownCmd
	}
	rn.tmu.Lock()
	defer rn.tmu.Unlock()
	switch {
	case rn.over || !rn.ready:
		return 0, ErrRunBusy
	case rn.running:
		return 0, ErrRunBusy
	case rn.count >= MaxCommandsPerRun:
		return 0, ErrTooMany
	}
	rn.seq++
	seq := rn.seq
	select {
	case rn.cmds <- commandReq{seq: seq, cmd: cmd}:
		rn.count++
		rn.running = true
		return seq, nil
	default:
		// The run goroutine is not receiving (it is ending): treat as over.
		rn.seq--
		return 0, ErrRunBusy
	}
}

// Leave ends a terminal run early (the visitor pressed "leave"). Same errors as Command for an
// unknown run or a bad token.
func (r *Runner) Leave(runID, token string) error {
	rn := r.lookupID(runID)
	if rn == nil || !rn.terminal {
		return ErrUnknownRun
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(rn.token)) != 1 {
		return ErrBadToken
	}
	rn.leaveOnce.Do(func() { close(rn.leave) })
	return nil
}

// CommandSeqFor returns the command seq to stamp on a Falco/Talon event naming pod: the one running
// now, or the one that ended less than 2 s ago, else 0 (absent). Best effort (ADR 0029).
func (r *Runner) CommandSeqFor(pod string) int {
	rn := r.lookup(pod)
	if rn == nil || !rn.terminal {
		return 0
	}
	rn.tmu.Lock()
	defer rn.tmu.Unlock()
	seq, _ := rn.activeSeqLocked()
	return seq
}

// activeSeqLocked returns the running command's seq and id, or the last finished one's if it ended
// within the 2 s window, else (0, ""). rn.tmu must be held.
func (rn *run) activeSeqLocked() (int, string) {
	if rn.running {
		return rn.curSeq, rn.curCmdID
	}
	if rn.lastSeq > 0 && time.Since(rn.lastEnded) < 2*time.Second {
		return rn.lastSeq, rn.lastCmdID
	}
	return 0, ""
}

// runTerminal keeps the pod alive and runs commands until an end condition, returning the final run
// state and detail (always `finished`, detail one of killed/left/idle/deadline - or `failed` on API
// shutdown). The scripted exec/select path is not used for an interactive scenario.
func (r *Runner) runTerminal(ctx context.Context, rn *run, sc scenarios.Scenario, log *slog.Logger) (string, string) {
	idle := sc.Idle()
	idleTimer := time.NewTimer(idle)
	defer idleTimer.Stop()

	rn.tmu.Lock()
	rn.ready = true
	rn.tmu.Unlock()
	defer func() {
		rn.tmu.Lock()
		rn.over = true
		rn.tmu.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			if r.base.Err() != nil {
				return StateFailed, "API shutting down"
			}
			return StateFinished, "deadline"
		case <-rn.gone:
			return StateFinished, "killed"
		case <-rn.leave:
			return StateFinished, "left"
		case <-idleTimer.C:
			return StateFinished, "idle"
		case req := <-rn.cmds:
			r.runCommand(ctx, rn, req, log)
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(idle)
		}
	}
}

// runCommand execs one command and publishes its events. A non-TTY command is cancelled after
// CommandTimeout; a TTY command runs until the pod is killed or the run ends.
func (r *Runner) runCommand(ctx context.Context, rn *run, req commandReq, log *slog.Logger) {
	seq, cmd := req.seq, req.cmd
	rn.tmu.Lock()
	rn.curSeq, rn.curCmdID = seq, cmd.ID
	rn.tmu.Unlock()

	r.emit(rn, "command", r.commandEvent(rn, CommandEvent{Seq: seq, ID: cmd.ID, State: CommandStarted}))

	cctx := ctx
	if !cmd.TTY {
		var cancel context.CancelFunc
		cctx, cancel = context.WithTimeout(ctx, r.cfg.CommandTimeout)
		defer cancel()
	}
	sink := &cmdSink{r: r, rn: rn, seq: seq, id: cmd.ID}
	code, err := r.exec.ExecStream(cctx, rn.namespace, rn.pod, scenarios.TerminalContainer,
		cmd.Command, cmd.TTY, sink.writer("stdout"), sink.writer("stderr"))
	sink.flush()
	if err != nil {
		log.Info("terminal command exec ended", "seq", seq, "id", cmd.ID, "err", err)
	}

	// The pod going away under the command is a kill, not an exit: wait briefly for the watch to
	// confirm the deletion (Talon's terminate deletes the pod a moment before the watch reports it).
	killed := rn.isGone()
	if !killed && err != nil && cctx.Err() == nil {
		t := time.NewTimer(r.cfg.DeleteWait)
		select {
		case <-rn.gone:
			killed = true
		case <-t.C:
		case <-ctx.Done():
		}
		t.Stop()
	}

	end := CommandEvent{Seq: seq, ID: cmd.ID, State: CommandExited, Truncated: sink.truncated}
	if killed {
		end.State = CommandKilled
	} else {
		ec := exitCode(code, err)
		end.ExitCode = &ec
		end.Achieved = cmd.Objective != "" && ec == 0
	}
	r.emit(rn, "command", r.commandEvent(rn, end))

	rn.tmu.Lock()
	rn.running = false
	rn.curSeq, rn.curCmdID = 0, ""
	rn.lastSeq, rn.lastCmdID, rn.lastEnded = seq, cmd.ID, r.now()
	rn.tmu.Unlock()
}

// commandEvent fills the fields common to every command event (run id, time, arm).
func (r *Runner) commandEvent(rn *run, ev CommandEvent) CommandEvent {
	ev.RunID = rn.id
	ev.At = r.now().UTC()
	ev.Arm = rn.arm
	return ev
}

// exitCode is the command's exit status: the shell's code when it exited (even non-zero, which is
// not an error - wget fails by design), 0 on a clean exit, and -1 when the exec was cut short (the
// non-TTY timeout) or failed to stream.
func exitCode(code int, err error) int {
	if err == nil {
		return code
	}
	if code != 0 {
		return code
	}
	return -1
}

// terminalDetected publishes a `detected` run event for the command the alert is about, once per
// command. The detection text is the command's own (the catalogue states it); the real correlation
// a visitor reads is the Falco event's command_seq.
func (r *Runner) terminalDetected(rn *run) {
	rn.tmu.Lock()
	seq, id := rn.activeSeqLocked()
	if seq == 0 || rn.detectedSeq == seq {
		rn.tmu.Unlock()
		return
	}
	rn.detectedSeq = seq
	rn.tmu.Unlock()
	cmd, _ := rn.sc.CommandByID(id)
	r.publish(rn, StateDetected, cmd.Detection)
}

// terminalResponded publishes a `responded` run event once per command. A terminate response then
// deletes the pod, which ends the run as `killed`; a quarantine leaves the pod running.
func (r *Runner) terminalResponded(rn *run) {
	rn.tmu.Lock()
	seq, id := rn.activeSeqLocked()
	if seq == 0 || rn.respondedSeq == seq {
		rn.tmu.Unlock()
		return
	}
	rn.respondedSeq = seq
	rn.tmu.Unlock()
	cmd, _ := rn.sc.CommandByID(id)
	r.publish(rn, StateResponded, cmd.Response)
}

// cmdSink turns the raw bytes of one command's stdout/stderr into `output` events: cleaned,
// scrubbed, chunked to commandChunkBytes, and capped per command and per run. It is written to
// concurrently (remotecommand streams stdout and stderr on separate goroutines), so every method
// takes the lock.
type cmdSink struct {
	r         *Runner
	rn        *run
	seq       int
	id        string
	mu        sync.Mutex
	pending   map[string][]byte // per stream, bytes not yet at a safe boundary
	cmdUsed   int
	truncated bool
}

func (s *cmdSink) writer(stream string) io.Writer { return sinkWriter{s: s, stream: stream} }

type sinkWriter struct {
	s      *cmdSink
	stream string
}

func (w sinkWriter) Write(p []byte) (int, error) {
	w.s.add(w.stream, p)
	return len(p), nil // never fail the exec stream on our account
}

func (s *cmdSink) add(stream string, p []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		s.pending = map[string][]byte{}
	}
	s.pending[stream] = append(s.pending[stream], p...)
	// Emit whole lines, or a full chunk's worth, as they accumulate; keep the tail (a partial line
	// or a split rune) for the next write or the final flush.
	for {
		buf := s.pending[stream]
		cut := cutPoint(buf)
		if cut == 0 {
			break
		}
		s.emitLocked(stream, buf[:cut])
		s.pending[stream] = append(buf[:0:0], buf[cut:]...)
	}
}

func (s *cmdSink) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for stream, buf := range s.pending {
		for len(buf) > 0 {
			n := len(buf)
			if n > commandChunkBytes {
				n = runeBoundary(buf, commandChunkBytes)
			}
			s.emitLocked(stream, buf[:n])
			buf = buf[n:]
		}
		s.pending[stream] = nil
	}
}

// emitLocked cleans and scrubs raw bytes, applies the per-command and per-run caps, and publishes
// one `output` event if anything survives. s.mu is held.
func (s *cmdSink) emitLocked(stream string, raw []byte) {
	text := sanitizeOutput(string(raw))
	if text == "" {
		return
	}
	b := []byte(text)
	// Per-command cap.
	if room := commandOutBytes - s.cmdUsed; len(b) > room {
		b = b[:runeBoundary(b, max(room, 0))]
		s.truncated = true
	}
	if len(b) == 0 {
		return
	}
	// Per-run cap (shared across all commands of the run).
	s.rn.tmu.Lock()
	room := runOutBytes - s.rn.runOut
	if room < 0 {
		room = 0
	}
	if len(b) > room {
		b = b[:runeBoundary(b, room)]
		s.truncated = true
	}
	s.rn.runOut += len(b)
	s.rn.tmu.Unlock()
	if len(b) == 0 {
		return
	}
	s.cmdUsed += len(b)
	s.r.emit(s.rn, "command", s.r.commandEvent(s.rn, CommandEvent{
		Seq: s.seq, ID: s.id, State: CommandOutput, Stream: stream, Chunk: string(b)}))
}

// cutPoint is how many bytes of buf are ready to emit: through the last newline, or a full chunk
// (to a rune boundary) once the buffer is large, else 0 (keep buffering).
func cutPoint(buf []byte) int {
	if i := lastIndexByte(buf, '\n'); i >= 0 {
		return i + 1
	}
	if len(buf) >= commandChunkBytes {
		return runeBoundary(buf, commandChunkBytes)
	}
	return 0
}

func lastIndexByte(b []byte, c byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// runeBoundary returns a length <= n that does not split a UTF-8 sequence.
func runeBoundary(b []byte, n int) int {
	if n >= len(b) {
		return len(b)
	}
	for n > 0 && !utf8.RuneStart(b[n]) {
		n--
	}
	return n
}

// sanitizeOutput forces valid UTF-8, keeps newline and tab but drops every other control character
// (so no ANSI escapes) and every invisible format character, then applies the ADR 0021 scrubber.
func sanitizeOutput(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	return webhook.Scrub(s)
}
