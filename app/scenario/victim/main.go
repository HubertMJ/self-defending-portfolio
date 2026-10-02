// victim: the "SDP Shop" that every attack-scenario pod serves, so a visitor can watch the thing
// being attacked change, and then be killed or cut off (ADR 0022).
//
// It is deliberately dumb. On start it writes a healthy shop into its docroot (an emptyDir: the
// image's root filesystem is read-only) and then serves two files from there on :8080:
//
//	/            index.html, the shop page (text/html, scripts blocked by CSP)
//	/state.json  {status, title, banner, checksum}, built from the docroot's state.json
//
// It never changes its own state. The scenario execs do, with nothing but busybox `echo` and `mv`
// into the same docroot (cluster/infra/sandbox/scenarios/scenarios.yaml): rewrite index.html to
// deface the shop, rewrite state.json to say what the attacker did. The server only reports what is
// on disk, so what the visitor sees is the effect of the real exec, not a script on the API side.
//
// Everything it reports is bounded, because the portfolio API reads it and relays it to the public
// page: status is one of three words (anything else reads "compromised" - a state file this program
// did not write is a tampered one), title and banner are clipped plain text, and checksum is the
// first 16 hex digits of the SHA-256 of index.html, so a defacement shows as a changed checksum even
// if the attacker leaves state.json alone.
//
// -check is the readiness probe (an exec probe: the sandbox network policy admits nothing but the
// portfolio API on :8080, not even the kubelet), and offline.sh uses it to read the state.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxTitle  = 80
	maxBanner = 120
	// What is read from the docroot at most: the state file is a few dozen bytes, a defaced page a
	// few hundred. A larger file is truncated, which for state.json means "invalid".
	maxState = 4 << 10
	maxIndex = 64 << 10
	// The per-run capture flag (SDP_FLAG) is "SDP{" + 16 hex + "}" = 21 bytes; the cap is slack for a
	// future format, not a contract. Longer is truncated rather than refused: the API is the only
	// writer of this env, so this is a safety bound, not input validation.
	maxFlag = 128
)

// The healthy shop. Plain, static, no script, no external reference.
const healthyIndex = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>SDP Shop</title></head>
<body>
<h1>SDP Shop</h1>
<p>Open for business. Every item ships signed, scanned and pinned by digest.</p>
<ul>
<li>Hardened hoodie - 42.00</li>
<li>Read-only root filesystem mug - 12.00</li>
<li>Signed sticker pack - 3.00</li>
</ul>
</body>
</html>
`

const healthyState = `{"status":"up","title":"SDP Shop","banner":"Open for business"}` + "\n"

// The three statuses the pod itself can report. "unreachable" and "gone" are what the API concludes
// when it cannot ask.
var statuses = map[string]bool{"up": true, "defaced": true, "compromised": true}

// State is the body of /state.json.
type State struct {
	Status   string `json:"status"`
	Title    string `json:"title"`
	Banner   string `json:"banner"`
	Checksum string `json:"checksum"`
}

// checkURL is the probe's URL for the listen address: always loopback, the port from addr, or 8080
// when addr names none (a bare host, or something unparsable - the probe must not crash on it).
func checkURL(addr string) string {
	port := "8080"
	if _, p, err := net.SplitHostPort(addr); err == nil && p != "" {
		port = p
	}
	return "http://" + net.JoinHostPort("127.0.0.1", port) + "/state.json"
}

func main() {
	docroot := flag.String("docroot", "/srv/shop", "writable directory the shop is served from (an emptyDir)")
	addr := flag.String("addr", ":8080", "listen address")
	lifetime := flag.Duration("lifetime", 120*time.Second, "exit after this long (a scenario pod lives at most 120 s)")
	check := flag.Bool("check", false, "probe mode: GET /state.json on the local server, print it, exit 0 if it answered")
	flag.Parse()

	if *check {
		os.Exit(probe(checkURL(*addr)))
	}

	if err := initDocroot(*docroot); err != nil {
		log.Fatalf("victim: %v", err)
	}
	// The terminal scenario's capture flag (ADR 0029/0032): the API sets SDP_FLAG per run, the shop
	// drops it at /srv/shop/.flag (0600) and never serves it - there is no route for it, only / and
	// /state.json. A terminal visitor can `cat` it (the `credentials` objective), which is the point:
	// reading it inside the pod is a real find, and also not the same as getting it out past a
	// default-deny network. Absent env (the one-click scenarios, and running the image on its own):
	// no flag file.
	if flag := strings.TrimSpace(os.Getenv("SDP_FLAG")); flag != "" {
		if err := writeFlag(*docroot, flag); err != nil {
			log.Fatalf("victim: flag: %v", err)
		}
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           &shop{docroot: *docroot},
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	// Bounded like the `sleep 120` this replaced: run on its own, the image still ends by itself. In
	// a pod, activeDeadlineSeconds ends it first.
	time.AfterFunc(*lifetime, func() { os.Exit(0) })
	log.Printf("victim: serving %s on %s", *docroot, *addr)
	log.Fatal(srv.ListenAndServe())
}

// initDocroot writes the healthy shop. Every write is a temp file and a rename, the same way the
// scenario execs replace files, so a reader never sees half a file.
func initDocroot(dir string) error {
	if err := writeAtomic(dir, "index.html", healthyIndex); err != nil {
		return err
	}
	return writeAtomic(dir, "state.json", healthyState)
}

func writeAtomic(dir, name, content string) error {
	tmp := filepath.Join(dir, "."+name)
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}

// writeFlag stores the per-run capture flag at <dir>/.flag, mode 0600. temp-then-rename like
// writeAtomic, so a concurrent reader never sees a half-written flag; both names are dotfiles with no
// route, so neither is ever served.
func writeFlag(dir, flag string) error {
	if len(flag) > maxFlag {
		flag = flag[:maxFlag]
	}
	tmp := filepath.Join(dir, ".flag.tmp")
	if err := os.WriteFile(tmp, []byte(flag+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, ".flag"))
}

type shop struct {
	docroot string

	mu   sync.Mutex
	last *State // the last valid state.json, served while the file on disk is not valid
}

func (s *shop) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch r.URL.Path {
	case "/":
		page, err := readCapped(filepath.Join(s.docroot, "index.html"), maxIndex)
		if err != nil {
			http.Error(w, "no page", http.StatusServiceUnavailable)
			return
		}
		// The page is attacker-writable by design; nothing it contains may run.
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		h.Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(page)
	case "/state.json":
		st, err := s.state()
		if err != nil {
			http.Error(w, "no state", http.StatusServiceUnavailable)
			return
		}
		body, _ := json.Marshal(st)
		h.Set("Content-Type", "application/json")
		_, _ = w.Write(append(body, '\n'))
	default:
		http.NotFound(w, r)
	}
}

// state reads the docroot's state.json and index.html into the bounded shape the API relays.
func (s *shop) state() (State, error) {
	var st State
	raw, err := readCapped(filepath.Join(s.docroot, "state.json"), maxState)
	if err == nil {
		err = json.Unmarshal(raw, &st)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		if s.last == nil {
			return State{}, err
		}
		st = *s.last
	} else {
		if !statuses[st.Status] {
			st.Status = "compromised"
		}
		st.Title = clip(st.Title, maxTitle)
		st.Banner = clip(st.Banner, maxBanner)
		saved := st
		s.last = &saved
	}
	st.Checksum = ""
	if page, err := readCapped(filepath.Join(s.docroot, "index.html"), maxIndex); err == nil {
		sum := sha256.Sum256(page)
		st.Checksum = hex.EncodeToString(sum[:])[:16]
	}
	return st, nil
}

func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

// clip makes s one line of printable text of at most n runes.
func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n])
	}
	return s
}

func probe(url string) int {
	client := &http.Client{
		Timeout: time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("no redirects")
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "victim -check:", err)
		return 1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxState))
	fmt.Print(string(bytes.TrimSpace(body)) + "\n")
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
