package lab

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/siem"
)

// maxRaw rejects an oversized GET /api/lab/raw answer outright: a VM run is a few dozen records of
// under 1 KiB each, so this is only the backstop if a run ever wrote far more than that.
const maxRaw = 256 << 10

// rawFields is the allow-list of leaf paths a raw record may keep: the sdp-lab fields a VM run
// writes (siem/fields/lab.yaml) that the /lab/ page shows. Anything else - including a field a
// future shipper might add - is dropped, and so is an allow-listed path that holds an object or an
// array instead of a single value.
var rawFields = map[string]bool{
	"@timestamp": true, "event.kind": true, "event.dataset": true, "event.code": true,
	"event.action": true, "event.ingested": true, "host.name": true,
	"lab.run_id": true, "lab.mode": true, "lab.variant": true, "lab.marker": true, "lab.offset_s": true,
	"process.pid": true, "process.name": true, "process.executable": true, "process.hash.sha256": true,
	"process.parent.name": true, "process.parent.pid": true,
	"file.path": true, "destination.ip": true, "destination.port": true,
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
// indexed.
type rawRun struct {
	RunID   string           `json:"run_id"`
	Records []map[string]any `json:"records"`
}

// Raw returns the newest isolated-VM run's sdp-lab records as JSON, or false when there is no such
// run in the window (or a query fails, or the answer is over the size cap). Cached for the TTL like
// Latest.
func (r *Reader) Raw(ctx context.Context) ([]byte, bool) {
	return r.raw.get(r, func() []byte { return r.fetchRaw(ctx) })
}

func (r *Reader) fetchRaw(ctx context.Context) []byte {
	now := r.now().UTC()
	q := siem.Query{
		TimeField: "@timestamp",
		Since:     now.Add(-streamLookback),
		Until:     now.Add(time.Hour),
		Filters:   []map[string]any{term("lab.mode", modeVM)},
		Size:      1,
		SortField: "@timestamp",
		Source:    []string{"lab.run_id"},
	}
	idx := []string{siem.LabStream}
	res, err := r.src.Search(ctx, idx, q)
	if err != nil || len(res.Hits) == 0 {
		return nil
	}
	var newest struct {
		Lab struct {
			RunID string `json:"run_id"`
		} `json:"lab"`
	}
	if !decode(res.Hits[0].Source, &newest) || newest.Lab.RunID == "" {
		return nil
	}
	q.Filters = append(q.Filters, term("lab.run_id", newest.Lab.RunID))
	q.Size = siem.MaxSize
	q.Source = rawSource
	if res, err = r.src.Search(ctx, idx, q); err != nil {
		return nil
	}
	type record struct {
		doc         map[string]any
		at, shipped time.Time
	}
	recs := make([]record, 0, len(res.Hits))
	for _, h := range res.Hits {
		if doc := allowLeaves(h.Source, ""); len(doc) > 0 {
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
	out := rawRun{RunID: newest.Lab.RunID, Records: make([]map[string]any, len(recs))}
	for i, rec := range recs {
		out.Records[i] = rec.doc
	}
	body, err := json.Marshal(out)
	if err != nil || len(body) > maxRaw {
		return nil
	}
	return body
}

// allowLeaves copies the allow-listed scalar leaves of a nested document, keeping its nesting; prefix
// is the dotted path of m. A flat dotted key ("event.code") is matched by the same path.
func allowLeaves(m map[string]any, prefix string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		switch v := v.(type) {
		case map[string]any:
			if sub := allowLeaves(v, path); len(sub) > 0 {
				out[k] = sub
			}
		case []any:
			// No allow-listed field is an array.
		default:
			if rawFields[path] {
				out[k] = v
			}
		}
	}
	return out
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
