package runner

// The attacker's terminal (ADR 0029). A scenario with `interactive: true` is not run by a single
// scripted exec: the pod is created and kept alive, and the visitor sends catalogue command *ids*
// (never free text - the contract's hard rule), one at a time, which the runner execs into the
// `target` container and streams back as `command` events. The run ends when the pod is killed by
// Talon (a detected/terminate command), when the visitor leaves, after the idle timeout without a
// command, or at the scenario deadline.
//
// Output is untrusted (it is whatever runs in the attacked pod printed): each complete line is forced
// to valid UTF-8, stripped of every control character except newline and tab (so no ANSI escapes) and
// of invisible format characters, then run through the ADR 0021 scrubber (URLs, IPs and in-cluster
// service names, loopback excepted); lines are batched into events and capped per command and per
// run, in bytes and in events (cmdSink below). The run's
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
	// Events, not only bytes, are bounded: a pod that writes one byte at a time would otherwise turn
	// 4 KiB into thousands of events and push the run's own events out of the run log.
	commandOutEvents = 64  // `output` events per command
	runOutEvents     = 300 // `output` events per run
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
// 409 (ErrRunBusy) for one already over - including one whose command loop has ended and whose pod
// is still being cleaned up, where a leave would change nothing - 401 for a bad token. A leave
// before the pod is ready is accepted: the loop sees it the moment it starts.
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
	rn.tmu.Lock()
	over := rn.over
	rn.tmu.Unlock()
	if over {
		return ErrRunBusy
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
	seq, _ := rn.activeSeqLocked(r.now())
	return seq
}

// activeSeqLocked returns the running command's seq and id, or the last finished one's if it ended
// within the 2 s window before now, else (0, ""). now is the runner's clock, the one lastEnded was
// read from. rn.tmu must be held.
func (rn *run) activeSeqLocked(now time.Time) (int, string) {
	if rn.running {
		return rn.curSeq, rn.curCmdID
	}
	if rn.lastSeq > 0 && now.Sub(rn.lastEnded) < 2*time.Second {
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
			// Idle counts from the command's start, not its end: a command that hangs is not
			// activity. The command itself is bounded by the idle time too (runCommand), so idle
			// still ends a run whose last command never returns.
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(idle)
			r.runCommand(ctx, rn, req, idle, log)
		}
	}
}

// runCommand execs one command and publishes its events. The command's context is cancelled when
// the run's deadline passes (ctx), when the visitor leaves, or when the pod is killed under it, so a
// command - a TTY shell included, whose empty stdin never yields EOF - never outlives the run or a
// leave. It is also cut off after its own bound - CommandTimeout (5 s), or TTYCommandTimeout (10 s)
// for a TTY command, which only a pod deletion is expected to end - or the run's idle time if that
// is shorter, since idle counts from the command's start.
func (r *Runner) runCommand(ctx context.Context, rn *run, req commandReq, idle time.Duration, log *slog.Logger) {
	seq, cmd := req.seq, req.cmd
	rn.tmu.Lock()
	rn.curSeq, rn.curCmdID = seq, cmd.ID
	rn.tmu.Unlock()

	r.emit(rn, "command", r.commandEvent(rn, CommandEvent{Seq: seq, ID: cmd.ID, State: CommandStarted}))

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	bound := r.cfg.CommandTimeout
	if cmd.TTY {
		bound = r.cfg.TTYCommandTimeout
	}
	if idle < bound {
		bound = idle
	}
	cmdCtx, cancelBound := context.WithTimeout(cctx, bound) // the command's own bound, a child of cctx
	defer cancelBound()
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

	sink := &cmdSink{rn: rn, publish: func(stream, chunk string) {
		r.emit(rn, "command", r.commandEvent(rn, CommandEvent{
			Seq: seq, ID: cmd.ID, State: CommandOutput, Stream: stream, Chunk: chunk}))
	}}
	code, err := r.exec.ExecStream(cmdCtx, rn.namespace, rn.pod, scenarios.TerminalContainer,
		cmd.Command, cmd.TTY, sink.writer("stdout"), sink.writer("stderr"))
	truncated := sink.finish()
	if err != nil {
		log.Info("terminal command exec ended", "seq", seq, "id", cmd.ID, "err", err)
	}

	// Did the command end because of its own bound (cctx still live), or because the visitor left?
	// Neither is a kill, and neither should wait for a pod deletion.
	timedOut := cctx.Err() == nil && cmdCtx.Err() != nil
	left := isClosed(rn.leave)

	// Otherwise the pod going away under the command is a kill, not an exit: if the exec ended
	// unexpectedly, wait briefly for the watch to confirm a deletion (Talon's terminate deletes the
	// pod a moment before the watch reports it). "Unexpectedly" is a transport error, or an exit
	// status above 128 - death by a signal (128+n): the exec stream reports a container killed under
	// the command as a clean (137, nil) or (143, nil), often before the watch has seen the deletion.
	// An ordinary exit (0-128) does not wait: that is the command's own result, and waiting on every
	// command would stall the slot. Neither does our own timeout or a leave, with no kill coming.
	killed := rn.isGone()
	if !killed && (err != nil || code > 128) && ctx.Err() == nil && !timedOut && !left {
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
		// Cut short (the command's bound, a leave, or a transport error) before the shell reported
		// a status: `exited` with no exit_code rather than a synthetic -1.
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
//
// A Falco alert for the run's pod is always a detection; only the command it is tied to is best
// effort. An alert that correlates to no command (it arrived more than the 2 s window after the
// command ended) is published once per run without a command_seq, rather than dropped - dropping it
// let Talon's later response be published with no detection before it.
func (r *Runner) terminalDetected(rn *run, rule string) {
	rn.tmu.Lock()
	seq, id := rn.activeSeqLocked(r.now())
	switch {
	case seq == 0 && rn.detectedZero, seq != 0 && rn.detectedSeq == seq:
		rn.tmu.Unlock()
		return
	case seq == 0:
		rn.detectedZero = true
	default:
		rn.detectedSeq = seq
	}
	rn.tmu.Unlock()
	if seq == 0 {
		r.publishCmd(rn, StateDetected, rule, 0)
		return
	}
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
	seq, id := rn.activeSeqLocked(r.now())
	var needDetect bool
	if seq != 0 {
		if rn.respondedSeq == seq {
			rn.tmu.Unlock()
			return
		}
		rn.respondedSeq = seq
		needDetect = rn.detectedSeq != seq
		rn.detectedSeq = seq
	} else {
		// A response that correlated to no command (it arrived more than the 2 s window after the
		// command ended): still record the run was answered, just without a command_seq. Once only,
		// so a retrying Talon cannot spam the feed. It needs a detection before it only if the run
		// has none at all: an earlier command's `detected` already says the run was seen, and a
		// backfilled one here would pair the response with a detection made up at the same instant.
		if rn.respondedZero {
			rn.tmu.Unlock()
			return
		}
		rn.respondedZero = true
		needDetect = !rn.detectedZero && rn.detectedSeq == 0
		rn.detectedZero = true
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

// cmdSink turns one command's stdout/stderr into `output` events. The output is attacker-controlled:
// whatever runs in the pod chooses every byte and every write boundary.
//
// The invariant, on which the scrubbing rests: text is sanitised and scrubbed only as a complete line -
// the bytes between two newlines of one stream, or the last bytes of the stream at its end - and
// nothing else is ever published. None of the scrubber's patterns (IPv4, IPv6, URL, `.svc` and
// `.cluster.local` names) can match across a newline, so a token always lies inside one unit and is
// seen whole, however the pod splits its writes and whatever bytes the sanitiser drops from between
// its parts. A line that does not end within maxLineBytes is therefore not cut and scrubbed in
// pieces (each piece would pass on its own); it is dropped whole and a marker is published in its
// place. Only after scrubbing is the text cut into events, so an event boundary can fall inside a
// replacement such as "[ip]" but never inside an address. (The unit is a line of one stream. A pod that
// spreads an address over two lines or two streams on purpose is encoding it, as it could with spaces
// or base64; no scrubber undoes that. The scrubber is for what tools print - ADR 0021.)
//
// What it bounds: the pending line per stream (maxLineBytes), the text of one event
// (commandChunkBytes), the text and the number of events per command and per run. Lines are batched:
// one Write publishes its complete lines together, so a burst of short lines is a few events, not one
// event per line (the run log and the stream's replay buffer count events, not bytes).
//
// It is written to concurrently (remotecommand streams stdout and stderr on separate goroutines) and
// may be written to after the command ended (client-go's SPDY path returns on context cancel without
// waiting for its reader goroutine), so every method takes the lock and writes after finish() are
// dropped.
type cmdSink struct {
	rn *run
	// publish sends one `output` event; set by runCommand, replaced in tests.
	publish func(stream, chunk string)

	mu        sync.Mutex
	streams   map[string]*sinkStream
	cmdUsed   int // bytes published for this command
	cmdEvents int // `output` events published for this command
	truncated bool
	capped    bool // a cap was hit; no more output is published for this command
	done      bool // the command's end event is being published; late writes are dropped
}

// sinkStream is one stream's state: the line being assembled, and the scrubbed text of complete lines
// not yet published.
type sinkStream struct {
	pending  []byte // bytes of the current line, no newline yet; never more than maxLineBytes
	skipping bool   // inside a line that exceeded maxLineBytes: discard up to its newline
	out      []byte // sanitised, scrubbed text waiting to be cut into events
}

// maxLineBytes is the longest line the sink will publish. No command of the catalogue prints anything
// near it; a longer line is dropped whole (see cmdSink) rather than scrubbed in parts.
const maxLineBytes = 2 << 10

// lineDropped stands in for a line longer than maxLineBytes.
const lineDropped = "[line too long, not shown]\n"

func (s *cmdSink) writer(stream string) io.Writer { return sinkWriter{s: s, stream: stream} }

type sinkWriter struct {
	s      *cmdSink
	stream string
}

func (w sinkWriter) Write(p []byte) (int, error) {
	w.s.add(w.stream, p)
	return len(p), nil // never fail the exec stream on our account
}

func (s *cmdSink) stream(name string) *sinkStream {
	if s.streams == nil {
		s.streams = map[string]*sinkStream{}
	}
	st := s.streams[name]
	if st == nil {
		st = &sinkStream{}
		s.streams[name] = st
	}
	return st
}

// add consumes one write. It walks p once, newline by newline, so its cost is linear in len(p) and
// the only bytes it keeps are an unfinished line (at most maxLineBytes) and less than one event of
// scrubbed text.
func (s *cmdSink) add(name string, p []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.capped {
		return
	}
	st := s.stream(name)
	for len(p) > 0 && !s.capped {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			// No newline in what is left: it is the start, or the continuation, of a line.
			if st.skipping {
				break
			}
			if len(st.pending)+len(p) > maxLineBytes {
				s.dropLineLocked(st)
				st.skipping = true
				break
			}
			st.pending = append(st.pending, p...)
			break
		}
		rest := p[:i+1]
		p = p[i+1:]
		switch {
		case st.skipping:
			st.skipping = false // the over-long line ends here; its marker was already queued
		case len(st.pending)+len(rest) > maxLineBytes:
			s.dropLineLocked(st)
		default:
			st.pending = append(st.pending, rest...)
			st.out = append(st.out, sanitizeOutput(string(st.pending))...)
			st.pending = st.pending[:0]
		}
		// Keep the queued text below one event while the write is still being walked.
		for len(st.out) >= commandChunkBytes && !s.capped {
			s.emitLocked(name, st, commandChunkBytes)
		}
	}
	// Publish what this write completed now rather than at the next one: the visitor is watching.
	s.drainLocked(name, st)
}

// dropLineLocked discards the line being assembled and queues the marker in its place. s.mu is held.
func (s *cmdSink) dropLineLocked(st *sinkStream) {
	st.pending = st.pending[:0]
	st.out = append(st.out, lineDropped...)
	s.truncated = true
}

// drainLocked publishes everything queued for a stream. s.mu is held.
func (s *cmdSink) drainLocked(name string, st *sinkStream) {
	for len(st.out) > 0 && !s.capped {
		s.emitLocked(name, st, commandChunkBytes)
	}
	if s.capped {
		st.out, st.pending = nil, nil
	}
}

// finish publishes each stream's last line (the stream has ended, so the line is complete as it is),
// stops the sink and reports whether anything was dropped. Flushing and stopping are one step under
// the lock: a write that arrives later from a still-draining exec stream is ignored, so no `output`
// follows the command's end event and nothing is lost unreported in between.
func (s *cmdSink) finish() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, name := range []string{"stdout", "stderr"} {
		st := s.streams[name]
		if st == nil {
			continue
		}
		if len(st.pending) > 0 && !st.skipping && !s.capped {
			st.out = append(st.out, sanitizeOutput(string(st.pending))...)
		}
		st.pending = nil
		s.drainLocked(name, st)
	}
	s.done = true
	return s.truncated
}

// emitLocked publishes at most max bytes from the front of st.out as one `output` event, on a rune
// boundary, applying the per-command and per-run caps on bytes and on events; hitting any of them sets
// truncated and stops further output for this command. It always consumes from st.out or sets capped,
// so its callers' loops end. s.mu is held.
func (s *cmdSink) emitLocked(name string, st *sinkStream, max int) {
	n := len(st.out)
	if n > max {
		// st.out is valid UTF-8 (sanitizeOutput), so a boundary lies within three bytes of max.
		if n = runeBoundary(st.out, max); n == 0 {
			n = max
		}
	}
	chunk := st.out[:n]
	if s.cmdEvents >= commandOutEvents {
		s.truncated, s.capped = true, true
		return
	}
	if room := commandOutBytes - s.cmdUsed; len(chunk) > room {
		chunk = chunk[:runeBoundary(chunk, room)]
		s.truncated, s.capped = true, true
	}
	s.rn.tmu.Lock()
	room := runOutBytes - s.rn.runOut
	if room < 0 {
		room = 0
	}
	if s.rn.runOutEvents >= runOutEvents {
		room = 0
	}
	if len(chunk) > room {
		chunk = chunk[:runeBoundary(chunk, room)]
		s.truncated, s.capped = true, true
	}
	if len(chunk) > 0 {
		s.rn.runOut += len(chunk)
		s.rn.runOutEvents++
	}
	s.rn.tmu.Unlock()
	text := string(chunk)
	st.out = st.out[n:]
	if text == "" {
		return
	}
	s.cmdUsed += len(text)
	s.cmdEvents++
	s.publish(name, text)
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
