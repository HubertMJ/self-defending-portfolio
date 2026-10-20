package lab

import (
	"context"
	"encoding/json"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/siem"
)

const (
	// streamLookback bounds the sdp-lab searches of GET /api/lab/vm and /api/lab/raw: the VM runs
	// daily, so three days still find the newest run after a missed day or two.
	streamLookback = 3 * 24 * time.Hour
	// maxMarkers caps the lifecycle markers one VM status reads: a run writes eight, so three days of
	// daily runs are about two dozen, and the cap leaves room for reruns.
	maxMarkers = 200
	// defaultDailyStart is the scheduled VM run's start, as an offset from 00:00 UTC (the siem01
	// timer's OnCalendar).
	defaultDailyStart = 3 * time.Hour
	// defaultRunningFor: a whole run, rollback to poweroff, takes a few minutes (190 s for the first
	// real one), so a run whose newest marker is half an hour old and that never requested poweroff
	// has died, not kept running.
	defaultRunningFor = 30 * time.Minute
	// stamp is the time format of every time this package writes (the run documents' own).
	stamp = "2006-01-02T15:04:05.000Z"
)

// vmStatus is GET /api/lab/vm's answer. The API never talks to the hypervisor: everything here is
// derived from the lifecycle markers the VM run writes to sdp-lab. state, last_restore and next_run
// are the /lab/ page's contract.
type vmStatus struct {
	State         string `json:"state"` // "running" | "off"
	LastRun       vmRun  `json:"last_run"`
	LastRestore   string `json:"last_restore,omitempty"` // the newest rollback to the clean snapshot
	SnapshotClean bool   `json:"snapshot_clean"`         // the last run began with a rollback
	NextRun       string `json:"next_run"`
	CheckedAt     string `json:"checked_at"`
}

type vmRun struct {
	ID         string `json:"id"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at,omitempty"` // when it requested poweroff; absent until then
}

// lifecycleMarker is one marker document of sdp-lab, as the search's _source filter returns it.
type lifecycleMarker struct {
	at    time.Time
	runID string
	name  string
}

// VM returns the lab VM's status as JSON, or false when no lifecycle marker is in the window (or the
// query fails). Cached for the TTL like Latest.
func (r *Reader) VM(ctx context.Context) ([]byte, bool) {
	return r.vm.get(ctx, r, r.fetchVM)
}

func (r *Reader) fetchVM(ctx context.Context) ([]byte, error) {
	now := r.now().UTC()
	res, err := r.src.Search(ctx, []string{siem.LabStream}, siem.Query{
		TimeField: "@timestamp",
		Since:     now.Add(-streamLookback),
		Until:     now.Add(time.Hour),
		Filters:   []map[string]any{term("event.action", "lifecycle"), term("lab.mode", modeVM)},
		Size:      maxMarkers,
		SortField: "@timestamp",
		Source:    []string{"@timestamp", "lab.run_id", "lab.marker"},
	})
	if err != nil {
		return nil, err
	}
	var markers []lifecycleMarker
	for _, h := range res.Hits {
		src := nest(h.Source)
		var doc struct {
			Timestamp string `json:"@timestamp"`
			Lab       struct {
				Marker string `json:"marker"`
			} `json:"lab"`
		}
		id := runID(src)
		if !decode(src, &doc) || id == "" || doc.Lab.Marker == "" {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, doc.Timestamp)
		if err != nil {
			continue
		}
		markers = append(markers, lifecycleMarker{at: at.UTC(), runID: id, name: doc.Lab.Marker})
	}
	st, ok := vmState(markers, now, r.runningFor, r.dailyStart)
	if !ok {
		return nil, nil
	}
	out, err := json.Marshal(st)
	if err != nil {
		return nil, nil
	}
	return out, nil
}

// vmState derives the status from the markers in any order: the newest run is the run of the newest
// marker; it is running while it has not requested poweroff and its newest marker is younger than
// runningFor. False when there is no marker.
func vmState(markers []lifecycleMarker, now time.Time, runningFor, dailyStart time.Duration) (vmStatus, bool) {
	if len(markers) == 0 {
		return vmStatus{}, false
	}
	newest := markers[0]
	var restore time.Time
	for _, m := range markers {
		if m.at.After(newest.at) {
			newest = m
		}
		if m.name == "rollback" && m.at.After(restore) {
			restore = m.at
		}
	}
	first := newest
	var poweroff time.Time
	for _, m := range markers {
		if m.runID != newest.runID {
			continue
		}
		// Markers are written to the second: a rollback in the same second as another is still first.
		if m.at.Before(first.at) || (m.at.Equal(first.at) && m.name == "rollback") {
			first = m
		}
		if m.name == "poweroff_requested" {
			poweroff = m.at
		}
	}
	st := vmStatus{
		State:         "off",
		LastRun:       vmRun{ID: newest.runID, StartedAt: first.at.Format(stamp)},
		SnapshotClean: first.name == "rollback",
		NextRun:       nextRun(now, dailyStart).Format(stamp),
		CheckedAt:     now.Format(stamp),
	}
	if !restore.IsZero() {
		st.LastRestore = restore.Format(stamp)
	}
	if !poweroff.IsZero() {
		st.LastRun.FinishedAt = poweroff.Format(stamp)
	} else if now.Sub(newest.at) < runningFor {
		st.State = "running"
	}
	return st, true
}

// nextRun is the first scheduled start (dailyStart after 00:00 UTC) strictly after now.
func nextRun(now time.Time, dailyStart time.Duration) time.Time {
	now = now.UTC()
	next := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).Add(dailyStart)
	for !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next
}
