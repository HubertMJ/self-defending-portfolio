package lab

import (
	"context"
	"encoding/json"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/siem"
)

const (
	// maxRaw caps a GET /api/lab/raw answer: a VM run is a few dozen records of under 1 KiB each, so
	// this only bites if a run ever wrote far more; the oldest records are then left out.
	maxRaw = 256 << 10
	// maxText caps every string a raw record keeps (a path, a hash, a time are far shorter).
	maxText = 512
	// runScan is how many of the newest VM records are read to find the newest well-formed run id.
	runScan = 50
)

var (
	// runIDPattern is the lab's run id (siem/fields/lab.yaml): lab-<UTC yyyymmddThhmmssZ>-<6 hex>.
	runIDPattern = regexp.MustCompile(`^lab-\d{8}T\d{6}Z-[0-9a-f]{6}$`)
	// eventCodePattern is a Sysmon EventID.
	eventCodePattern = regexp.MustCompile(`^\d{1,3}$`)
	// beaconNet is the documentation network (TEST-NET-2) the lab's beacon receiver is in: any other
	// destination.ip is not the lab's and is never published.
	beaconNet = netip.MustParsePrefix("198.51.100.0/24")
)

// rawFields is the allow-list of leaf paths a raw record may keep, each with the check its value
// must pass: the sdp-lab fields a VM run writes (siem/fields/lab.yaml) that the /lab/ page shows.
// Anything else - including a field a future shipper might add - is dropped, and so is an
// allow-listed field whose value fails its check (an object, an array, a string where a number
// belongs, an over-long string, an address outside the lab's).
var rawFields = map[string]func(any) bool{
	"@timestamp": isText, "event.kind": isText, "event.dataset": isText,
	"event.code": textMatching(eventCodePattern), "event.action": isText, "event.ingested": isText,
	"host.name":  isText,
	"lab.run_id": textMatching(runIDPattern), "lab.mode": isText, "lab.variant": isNumber,
	"lab.marker": isText, "lab.offset_s": isNumber,
	"process.pid": isNumber, "process.name": isText, "process.executable": isText,
	"process.hash.sha256": isText, "process.parent.name": isText, "process.parent.pid": isNumber,
	"file.path": isText, "destination.ip": isLabAddress, "destination.port": isNumber,
}

func isText(v any) bool {
	s, ok := v.(string)
	return ok && len(s) <= maxText
}

// isNumber: a JSON number (encoding/json decodes every one to float64).
func isNumber(v any) bool {
	_, ok := v.(float64)
	return ok
}

func textMatching(re *regexp.Regexp) func(any) bool {
	return func(v any) bool { return isText(v) && re.MatchString(v.(string)) }
}

func isLabAddress(v any) bool {
	if !isText(v) {
		return false
	}
	a, err := netip.ParseAddr(v.(string))
	return err == nil && beaconNet.Contains(a)
}

// rawSource is rawFields as a _source filter: the first allow-list, enforced by OpenSearch.
var rawSource = func() []string {
	out := make([]string, 0, len(rawFields))
	for f := range rawFields {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}()

// rawRun is GET /api/lab/raw's answer: the newest VM run's records, oldest first, each nested as
// indexed. Truncated says records were left out: the run had more than one search returns, or the
// oldest were dropped to fit maxRaw.
type rawRun struct {
	RunID     string            `json:"run_id"`
	Records   []json.RawMessage `json:"records"`
	Truncated bool              `json:"truncated,omitempty"`
}

// Raw returns the newest isolated-VM run's sdp-lab records as JSON, or false when there is no such
// run in the window (or a query fails). Cached for the TTL like Latest.
func (r *Reader) Raw(ctx context.Context) ([]byte, bool) {
	return r.raw.get(ctx, r, r.fetchRaw)
}

func (r *Reader) fetchRaw(ctx context.Context) ([]byte, error) {
	now := r.now().UTC()
	q := siem.Query{
		TimeField: "@timestamp",
		Since:     now.Add(-streamLookback),
		Until:     now.Add(time.Hour),
		Filters:   []map[string]any{term("lab.mode", modeVM)},
		Size:      runScan,
		SortField: "@timestamp",
		Source:    []string{"lab.run_id"},
	}
	idx := []string{siem.LabStream}
	res, err := r.src.Search(ctx, idx, q)
	if err != nil {
		return nil, err
	}
	// The newest record with a well-formed run id names the run; a malformed id is skipped.
	id := ""
	for _, h := range res.Hits {
		if id = runID(nest(h.Source)); id != "" {
			break
		}
	}
	if id == "" {
		return nil, nil
	}
	q.Filters = append(q.Filters, term("lab.run_id", id))
	q.Size = siem.MaxSize
	q.Source = rawSource
	if res, err = r.src.Search(ctx, idx, q); err != nil {
		return nil, err
	}
	type record struct {
		doc         map[string]any
		at, shipped time.Time
	}
	recs := make([]record, 0, len(res.Hits))
	for _, h := range res.Hits {
		if doc := allowLeaves(nest(h.Source), ""); len(doc) > 0 {
			recs = append(recs, record{doc: doc, at: timeAt(doc, "@timestamp"), shipped: timeAt(doc, "event", "ingested")})
		}
	}
	// Oldest first; markers written in the same second (drained, poweroff_requested) keep the order
	// they were shipped in.
	sort.SliceStable(recs, func(i, j int) bool {
		if !recs[i].at.Equal(recs[j].at) {
			return recs[i].at.Before(recs[j].at)
		}
		return recs[i].shipped.Before(recs[j].shipped)
	})
	out := rawRun{RunID: id, Records: make([]json.RawMessage, 0, len(recs)), Truncated: res.Total > len(res.Hits)}
	for _, rec := range recs {
		b, err := json.Marshal(rec.doc)
		if err != nil {
			continue
		}
		out.Records = append(out.Records, b)
	}
	// Over the cap, the oldest records go first: the envelope (with "truncated") plus each record and
	// the comma between two.
	env, _ := json.Marshal(rawRun{RunID: id, Records: []json.RawMessage{}, Truncated: true})
	size := len(env) + max(len(out.Records)-1, 0)
	for _, b := range out.Records {
		size += len(b)
	}
	for size > maxRaw && len(out.Records) > 0 {
		size -= len(out.Records[0]) + min(len(out.Records)-1, 1)
		out.Records = out.Records[1:]
		out.Truncated = true
	}
	body, err := json.Marshal(out)
	if err != nil || len(body) > maxRaw {
		return nil, nil
	}
	return body, nil
}

// allowLeaves copies the allow-listed leaves of a nested document whose values pass their checks,
// keeping its nesting; prefix is the dotted path of m.
func allowLeaves(m map[string]any, prefix string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		if sub, ok := v.(map[string]any); ok {
			if sub := allowLeaves(sub, path); len(sub) > 0 {
				out[k] = sub
			}
		} else if check := rawFields[path]; check != nil && check(v) {
			out[k] = v
		}
	}
	return out
}

// nest returns a document with its flat dotted keys ("lab.run_id", as older documents were written)
// moved into the nested form the stream's documents use now, so both read alike. Keys are taken in
// sorted order, so where a dotted key collides with a value that is not an object ("lab": "x" and
// "lab.run_id") the result does not depend on map order: the shorter key is kept, the dotted one
// dropped. The input is not modified.
func nest(m map[string]any) map[string]any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]any, len(m))
	for _, k := range keys {
		v := m[k]
		if sub, ok := v.(map[string]any); ok {
			v = nest(sub)
		}
		parts := strings.Split(k, ".")
		dst := out
		for _, p := range parts[:len(parts)-1] {
			next, exists := dst[p]
			if !exists {
				next = map[string]any{}
				dst[p] = next
			}
			if dst, _ = next.(map[string]any); dst == nil {
				break
			}
		}
		if dst == nil {
			continue
		}
		last := parts[len(parts)-1]
		existing, exists := dst[last]
		if !exists {
			dst[last] = v
			continue
		}
		// Both forms of one object ("event": {...} and "event.code"): merge, the first one winning.
		em, ok1 := existing.(map[string]any)
		vm, ok2 := v.(map[string]any)
		if ok1 && ok2 {
			for kk, vv := range vm {
				if _, dup := em[kk]; !dup {
					em[kk] = vv
				}
			}
		}
	}
	return out
}

// runID is a nested document's lab.run_id when it is well formed, else "".
func runID(doc map[string]any) string {
	lab, _ := doc["lab"].(map[string]any)
	id, _ := lab["run_id"].(string)
	if !runIDPattern.MatchString(id) {
		return ""
	}
	return id
}

// timeAt reads the time at a nested path of a record; the zero time when absent or not a time.
func timeAt(m map[string]any, path ...string) time.Time {
	for _, k := range path[:len(path)-1] {
		m, _ = m[k].(map[string]any)
	}
	s, _ := m[path[len(path)-1]].(string)
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}
