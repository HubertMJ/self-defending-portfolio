package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadToken(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte("  abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path, want, log string
	}{
		{"a token, trimmed", file, "abc", ""},
		{"no file: the trigger is simply off", filepath.Join(dir, "missing"), "", `level=INFO msg="lab run trigger off" reason="no token file"`},
		{"unreadable (a directory): a warning", dir, "", `level=WARN msg="lab run trigger off: token file unreadable"`},
	} {
		var logs strings.Builder
		got := readToken(tc.path, slog.New(slog.NewTextHandler(&logs, nil)))
		if string(got) != tc.want || !strings.Contains(logs.String(), tc.log) || (tc.log == "" && logs.Len() != 0) {
			t.Errorf("%s: token %q, log %q", tc.name, got, logs.String())
		}
	}
}
