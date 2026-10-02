package runner

// The victim poller (ADR 0021). A scenario marked `victim: true` runs an image that serves a tiny
// fake shop on :8080, with its own state in /state.json ({status, title, banner, checksum}); the
// scenario's command changes that state (defaces the page, drops a payload). While the run is
// active the API reads the state every 500 ms and publishes `event: victim` when it changes, so
// the page can show the shop being attacked, then cut off (quarantine: the probe stops getting
// through) or killed (terminate: the pod is gone).
//
// The API is the only client of that server - there is no Service and no route, and the sandbox
// network policy admits port 8080 from the API's pods only - but what it reads is still written by
// whatever runs in the attacked pod, so the reader treats it as hostile:
//
//   - the address is the pod IP from the pod object, never a name to resolve, and never published;
//     a hostNetwork pod (which Pod Security forbids in `sandbox` anyway) is not probed at all;
//   - one request per probe, a new connection each time (no keep-alive: an established connection
//     could outlive the quarantine policy and make the isolation look like it failed), no proxy;
//   - 300 ms for the whole exchange, response headers capped, body capped at 4 KiB;
//   - no redirects followed, 200 and application/json only;
//   - status must be one of the three the app defines, strings are stripped to plain text and
//     length-capped, the checksum must be short hex; anything else is "unreachable".
//
// Failure is the signal, not an error: "unreachable" during a quarantine is the visible proof that
// Cilium cut the pod off, and "gone" after Talon's terminate is the proof that it is dead.

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Victim statuses, as published in `event: victim`.
const (
	VictimUp          = "up"
	VictimDefaced     = "defaced"
	VictimCompromised = "compromised"
	VictimUnreachable = "unreachable"
	VictimGone        = "gone"
)

// Limits on what the victim app may say.
const (
	victimMaxBody   = 4 << 10
	victimMaxTitle  = 80
	victimMaxBanner = 120
)

var victimChecksum = regexp.MustCompile(`^[0-9a-f]{1,16}$`)

// VictimEvent is the public `event: victim` payload. Title, Banner and Checksum are empty unless the
// app answered; ProbeMS is how long the probe took (for "unreachable", how long until it gave up).
type VictimEvent struct {
	RunID    string    `json:"run_id"`
	Pod      string    `json:"pod"`
	At       time.Time `json:"at"`
	Status   string    `json:"status"`
	Title    string    `json:"title"`
	Banner   string    `json:"banner"`
	ProbeMS  int64     `json:"probe_ms"`
	Checksum string    `json:"checksum"`
	// Arm is "guarded" or "unguarded" on a compare run (ADR 0031), absent otherwise.
	Arm string `json:"arm,omitempty"`
}

// same reports whether two observations show the same thing (time and latency aside).
func (v VictimEvent) same(o VictimEvent) bool {
	return v.Status == o.Status && v.Title == o.Title && v.Banner == o.Banner && v.Checksum == o.Checksum
}

type victimProber struct {
	client  *http.Client
	port    int
	timeout time.Duration
}

func newVictimProber(port int, timeout time.Duration) *victimProber {
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: timeout}).DialContext,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 4 << 10,
	}
	return &victimProber{
		port:    port,
		timeout: timeout,
		client: &http.Client{
			Transport: tr,
			Timeout:   timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // a 3xx is then not a 200, so "unreachable"
			},
		},
	}
}

// probe reads the victim's state once. It returns Status, Title, Banner, Checksum and ProbeMS set.
func (p *victimProber) probe(ctx context.Context, podIP string) VictimEvent {
	start := time.Now()
	ev := p.read(ctx, podIP)
	ev.ProbeMS = time.Since(start).Milliseconds()
	return ev
}

func (p *victimProber) read(ctx context.Context, podIP string) VictimEvent {
	down := VictimEvent{Status: VictimUnreachable}
	ip := net.ParseIP(podIP)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return down
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	url := "http://" + net.JoinHostPort(ip.String(), strconv.Itoa(p.port)) + "/state.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return down
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return down
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return down
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return down
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, victimMaxBody+1))
	if err != nil || len(body) > victimMaxBody {
		return down
	}
	var st struct {
		Status   string `json:"status"`
		Title    string `json:"title"`
		Banner   string `json:"banner"`
		Checksum string `json:"checksum"`
	}
	if err := json.Unmarshal(body, &st); err != nil {
		return down
	}
	switch st.Status {
	case VictimUp, VictimDefaced, VictimCompromised:
	default:
		return down
	}
	ev := VictimEvent{Status: st.Status, Title: plainText(st.Title, victimMaxTitle), Banner: plainText(st.Banner, victimMaxBanner)}
	if victimChecksum.MatchString(st.Checksum) {
		ev.Checksum = st.Checksum
	}
	return ev
}

// plainText keeps printable characters only (no control characters, no invisible format characters
// such as bidi overrides or zero-width spaces, no angle brackets, so not even a careless renderer
// could be handed markup), collapses whitespace and caps the length in runes.
func plainText(s string, n int) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			space = b.Len() > 0
			continue
		case !unicode.IsPrint(r), r == '<', r == '>', r == unicode.ReplacementChar:
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	out := []rune(b.String())
	if len(out) > n {
		out = append(out[:n-1], '…')
	}
	return string(out)
}

// pollVictim probes the pod every VictimInterval until ctx ends or the pod is going away, and
// publishes each change of state. last is what was published before (zero: nothing yet). "gone" is
// published once the pod is being deleted by someone other than the runner (Talon).
//
// Two kinds of failure are not reported as "unreachable": one before the app has ever answered
// (it is still starting - the app answers 503 until its state exists), and one that turns out to be
// the pod dying - Talon's delete makes the probe fail a moment before the watch reports the
// deletion, so a failure after a good answer waits one interval for that report and says "gone"
// instead if it comes.
func (r *Runner) pollVictim(ctx context.Context, rn *run, podIP string, last VictimEvent) {
	t := time.NewTicker(r.cfg.VictimInterval)
	defer t.Stop()
	for {
		select {
		case <-rn.gone:
			r.publishVictimGone(rn)
			return
		default:
		}
		ev := r.prober.probe(ctx, podIP)
		if ctx.Err() != nil {
			return // stopped mid-probe: the failure is ours, not the pod's
		}
		select {
		case <-rn.gone:
			r.publishVictimGone(rn)
			return
		default:
		}
		if ev.Status == VictimUnreachable && last.Status == "" {
			ev = last // still starting
		}
		if ev.Status == VictimUnreachable && last.Status != VictimUnreachable {
			grace := time.NewTimer(r.cfg.VictimInterval)
			select {
			case <-ctx.Done():
				grace.Stop()
				return
			case <-rn.gone:
				grace.Stop()
				r.publishVictimGone(rn)
				return
			case <-grace.C:
			}
		}
		if ev.Status != "" && (last.Status == "" || !ev.same(last)) {
			last = ev
			ev.RunID, ev.Pod, ev.At = rn.id, rn.pod, r.now().UTC()
			r.emitVictim(rn, ev)
			if ev.Status == VictimUnreachable {
				// Signal the quarantine linger that the cut is visible now (FIX 1); non-blocking,
				// coalesced to the last one, so the linger waits on a cut after the response.
				select {
				case rn.unreachable <- struct{}{}:
				default:
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-rn.gone:
			r.publishVictimGone(rn)
			return
		case <-t.C:
		}
	}
}

func (r *Runner) publishVictimGone(rn *run) {
	rn.victimGoneOnce.Do(func() {
		r.emitVictim(rn, VictimEvent{RunID: rn.id, Pod: rn.pod, At: r.now().UTC(), Status: VictimGone})
	})
}
