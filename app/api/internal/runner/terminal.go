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
	"bytes"
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
		if r.wasTerminal(runID) {
			return 0, ErrRunBusy // the run existed and is over
		}
		return 0, ErrUnknownRun
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(rn.token)) != 1 {
		return 0, ErrBadToken
	}
	cmd, ok := rn.sc.CommandByID(commandID)
	if !ok {
		return 0, ErrUnknownCmd
	}
	// Reserve the slot under the lock, then hand the command to the loop. The loop takes it only if
	// it is still accepting; if it has ended first, loopDone unblocks us and the slot is returned,
	// so a command is never acknowledged (202 + seq) without running, and `running` never sticks.
	rn.tmu.Lock()
	switch {
	case rn.over || !rn.ready:
		rn.tmu.Unlock()
		return 0, ErrRunBusy
	case rn.running:
		rn.tmu.Unlock()
		return 0, ErrRunBusy
	case rn.count >= MaxCommandsPerRun:
		rn.tmu.Unlock()
		return 0, ErrTooMany
	}
	rn.running = true
	rn.count++
	rn.seq++
	seq := rn.seq
	rn.tmu.Unlock()

	select {
	case rn.cmds <- commandReq{seq: seq, cmd: cmd}:
		return seq, nil
	case <-rn.loopDone:
		rn.tmu.Lock()
		rn.running = false
		rn.count--
		rn.seq--
		rn.over = true
		rn.tmu.Unlock()
		return 0, ErrRunBusy
	}
}

// Leave ends a terminal run early (the visitor pressed "leave"). 404 for a run that never existed,
// 409 (ErrRunBusy) for one already over, 401 for a bad token.
func (r *Runner) Leave(runID, token string) error {
	rn := r.lookupID(runID)
	if rn == nil || !rn.terminal {
		if r.wasTerminal(runID) {
			return ErrRunBusy
		}
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
func (r *Runner) CommandSeqFor(namespace, pod string) int {
	rn := r.lookup(namespace, pod)
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

// isClosed reports whether a signalling channel has been closed, without blocking.
func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
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
	// Stop accepting commands the instant the loop ends: set `over` and close loopDone, which
	// unblocks any Command handing off a request so it returns 409 instead of being acknowledged
	// and never run.
	defer func() {
		rn.tmu.Lock()
		rn.over = true
		rn.tmu.Unlock()
		close(rn.loopDone)
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

// runCommand execs one command and publishes its events. The command's context is cancelled when
// the run's deadline passes (ctx), when the visitor leaves, or when the pod is killed under it, so a
// command - a TTY shell included, whose empty stdin never yields EOF - never outlives the run or a
// leave. A non-TTY command is additionally cut off after CommandTimeout.
func (r *Runner) runCommand(ctx context.Context, rn *run, req commandReq, log *slog.Logger) {
	seq, cmd := req.seq, req.cmd
	rn.tmu.Lock()
	rn.curSeq, rn.curCmdID = seq, cmd.ID
	rn.tmu.Unlock()

	r.emit(rn, "command", r.commandEvent(rn, CommandEvent{Seq: seq, ID: cmd.ID, State: CommandStarted}))

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmdCtx := cctx // the timeout context, a child of cctx, for a non-TTY command
	if !cmd.TTY {
		var c2 context.CancelFunc
		cmdCtx, c2 = context.WithTimeout(cctx, r.cfg.CommandTimeout)
		defer c2()
	}
	// Leave and a kill end the command too (ctx already ends it at the run deadline).
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-rn.leave:
			cancel()
		case <-rn.gone:
			cancel()
		case <-stop:
		}
	}()

	sink := &cmdSink{r: r, rn: rn, seq: seq, id: cmd.ID}
	code, err := r.exec.ExecStream(cmdCtx, rn.namespace, rn.pod, scenarios.TerminalContainer,
		cmd.Command, cmd.TTY, sink.writer("stdout"), sink.writer("stderr"))
	sink.flush()
	truncated := sink.close()
	if err != nil {
		log.Info("terminal command exec ended", "seq", seq, "id", cmd.ID, "err", err)
	}

	// Did the command end because of its own non-TTY timeout (cctx still live), or because the
	// visitor left? Neither is a kill, and neither should wait for a pod deletion.
	timedOut := !cmd.TTY && cctx.Err() == nil && cmdCtx.Err() != nil
	left := isClosed(rn.leave)

	// Otherwise the pod going away under the command is a kill, not an exit: if the exec ended
	// unexpectedly, wait briefly for the watch to confirm a deletion (Talon's terminate deletes the
	// pod a moment before the watch reports it). Not for our own timeout or a leave, which would
	// otherwise stall the slot for DeleteWait with no kill coming.
	killed := rn.isGone()
	if !killed && err != nil && ctx.Err() == nil && !timedOut && !left {
		t := time.NewTimer(r.cfg.DeleteWait)
		select {
		case <-rn.gone:
			killed = true
		case <-t.C:
		case <-ctx.Done():
		}
		t.Stop()
	}

	end := CommandEvent{Seq: seq, ID: cmd.ID, Truncated: truncated}
	switch {
	case killed:
		end.State = CommandKilled
	case err == nil:
		// A clean exit, including a non-zero shell status (wget failing by design): that is the
		// command's own result, reported as the exit code.
		end.State = CommandExited
		end.ExitCode = &code
		end.Achieved = cmd.Objective != "" && code == 0
	default:
		// Cut short (the 5 s non-TTY timeout, a leave, or a transport error) before the shell
		// reported a status: `exited` with no exit_code rather than a synthetic -1.
		end.State = CommandExited
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

// terminalDetected publishes a `detected` run event for the command the alert is about, once per
// command, carrying its seq so the page can tie the detection to the keystroke. The detail is the
// Falco rule that fired (the honest name, even for an `allowed`/`prevented` command that has no rule
// of its own in the catalogue); it falls back to the command's catalogue detection if no rule was
// passed.
func (r *Runner) terminalDetected(rn *run, rule string) {
	rn.tmu.Lock()
	seq, id := rn.activeSeqLocked()
	if seq == 0 || rn.detectedSeq == seq {
		rn.tmu.Unlock()
		return
	}
	rn.detectedSeq = seq
	rn.tmu.Unlock()
	if rule == "" {
		cmd, _ := rn.sc.CommandByID(id)
		rule = cmd.Detection
	}
	r.publishCmd(rn, StateDetected, rule, seq)
}

// terminalResponded publishes a `responded` run event once per command, backfilling `detected`
// first if the response beat the alert (so a terminal run never shows responded before detected). A
// terminate response then deletes the pod, which ends the run as `killed`; a quarantine leaves the
// pod running.
func (r *Runner) terminalResponded(rn *run) {
	rn.tmu.Lock()
	seq, id := rn.activeSeqLocked()
	if seq != 0 {
		if rn.respondedSeq == seq {
			rn.tmu.Unlock()
			return
		}
		rn.respondedSeq = seq
	} else {
		// A response that correlated to no command (it arrived more than the 2 s window after the
		// command ended): still record the run was answered, just without a command_seq. Once only,
		// so a retrying Talon cannot spam the feed.
		if rn.respondedZero {
			rn.tmu.Unlock()
			return
		}
		rn.respondedZero = true
	}
	needDetect := seq != 0 && rn.detectedSeq != seq
	if needDetect {
		rn.detectedSeq = seq
	}
	rn.tmu.Unlock()
	var detection, response string
	if seq != 0 {
		cmd, _ := rn.sc.CommandByID(id)
		detection, response = cmd.Detection, cmd.Response
	}
	if needDetect {
		r.publishCmd(rn, StateDetected, detection, seq)
	}
	r.publishCmd(rn, StateResponded, response, seq)
}

// cmdSink turns one command's stdout/stderr into `output` events. The output is attacker-controlled,
// so it is sanitised and scrubbed one whole line at a time - never across a chunk boundary, so a cut
// cannot split an IP, URL or `.svc` name and let both halves past the scrubber - and only then split
// into events of at most commandChunkBytes, with a per-command and a per-run cap. It is written to
// concurrently (remotecommand streams stdout and stderr on separate goroutines) and may be written
// to after the command ended (client-go's SPDY path returns on context cancel without waiting for
// its reader goroutine), so every method takes the lock and writes after close() are dropped.
type cmdSink struct {
	r   *Runner
	rn  *run
	seq int
	id  string

	mu        sync.Mutex
	pending   map[string][]byte // per stream, bytes not yet at a line boundary
	cmdUsed   int               // bytes published for this command
	truncated bool
	capped    bool // a cap was hit; no more output is published for this command
	done      bool // the command's end event was published; late writes are dropped
}

// maxLineBytes bounds the pending buffer per stream. A line longer than this (no newline) is
// processed as one unit, so the buffer never grows without limit and add() always makes progress -
// even on a run of UTF-8 continuation bytes, where a rune-boundary cut could otherwise be zero.
const maxLineBytes = 8 << 10

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
	if s.done || s.capped {
		return
	}
	if s.pending == nil {
		s.pending = map[string][]byte{}
	}
	buf := append(s.pending[stream], p...)
	for {
		cut := lineCut(buf)
		if cut == 0 {
			break
		}
		s.emitLineLocked(stream, buf[:cut])
		buf = append(buf[:0:0], buf[cut:]...)
		if s.capped {
			buf = nil
			break
		}
	}
	s.pending[stream] = buf
}

func (s *cmdSink) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for stream, buf := range s.pending {
		if len(buf) > 0 && !s.capped {
			s.emitLineLocked(stream, buf)
		}
		s.pending[stream] = nil
	}
}

// close stops the sink and reports whether anything was dropped. After it, a late write from a
// still-draining exec stream is ignored (no `output` after the command's end event).
func (s *cmdSink) close() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	return s.truncated
}

// lineCut is how many leading bytes of buf form the next unit to emit: through the first newline, or
// the whole maxLineBytes once the buffer reaches that without one, else 0. It is > 0 whenever a
// newline exists or the buffer is large, so add() terminates.
func lineCut(buf []byte) int {
	if i := bytes.IndexByte(buf, '\n'); i >= 0 {
		return i + 1
	}
	if len(buf) >= maxLineBytes {
		return maxLineBytes
	}
	return 0
}

// emitLineLocked sanitises and scrubs one line as a unit, then publishes it as one or more `output`
// events of at most commandChunkBytes on rune boundaries, applying the per-command then per-run cap;
// either cap sets truncated and stops further output for this command. s.mu is held.
func (s *cmdSink) emitLineLocked(stream string, raw []byte) {
	text := sanitizeOutput(string(raw))
	for len(text) > 0 && !s.capped {
		n := len(text)
		if n > commandChunkBytes {
			n = runeBoundary([]byte(text[:commandChunkBytes+1]), commandChunkBytes)
		}
		chunk := []byte(text[:n])
		text = text[n:]
		if room := commandOutBytes - s.cmdUsed; len(chunk) > room {
			chunk = chunk[:runeBoundary(chunk, room)]
			s.truncated, s.capped = true, true
		}
		if len(chunk) == 0 {
			continue
		}
		s.rn.tmu.Lock()
		room := runOutBytes - s.rn.runOut
		if room < 0 {
			room = 0
		}
		if len(chunk) > room {
			chunk = chunk[:runeBoundary(chunk, room)]
			s.truncated, s.capped = true, true
		}
		s.rn.runOut += len(chunk)
		s.rn.tmu.Unlock()
		if len(chunk) == 0 {
			continue
		}
		s.cmdUsed += len(chunk)
		s.r.emit(s.rn, "command", s.r.commandEvent(s.rn, CommandEvent{
			Seq: s.seq, ID: s.id, State: CommandOutput, Stream: stream, Chunk: string(chunk)}))
	}
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
