package checkers

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/config"
)

func preserveFullCheckOutputConfig(t *testing.T) {
	t.Helper()
	old := config.Get().All
	t.Cleanup(func() {
		config.Get().All = old
	})
}

func TestFullCheckSaveJSON(t *testing.T) {
	preserveFullCheckOutputConfig(t)

	dir := t.TempDir()
	config.Get().All.Prefix = filepath.Join(dir, "report-")
	config.Get().All.TsFormat = "20060102T150405.000000000"
	config.Get().All.Format = "json"

	dto := &FullCheckDto{Whoami: &FullCheckWhoamiDto{
		Status: FullCheckStatusDto{Msg: "Ok", Code: "OK"},
		Ip:     "192.0.2.1",
	}}
	if err := fullCheckSave(dto); err != nil {
		t.Fatalf("fullCheckSave: %v", err)
	}

	path := singleReportPath(t, dir, ".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	var got FullCheckDto
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if got.Whoami == nil || got.Whoami.Ip != "192.0.2.1" {
		t.Fatalf("unexpected decoded report: %+v", got)
	}
}

func TestFullCheckSaveYAML(t *testing.T) {
	preserveFullCheckOutputConfig(t)

	dir := t.TempDir()
	config.Get().All.Prefix = filepath.Join(dir, "report-")
	config.Get().All.TsFormat = "20060102T150405.000000000"
	config.Get().All.Format = "yaml"

	if err := fullCheckSave(&FullCheckDto{}); err != nil {
		t.Fatalf("fullCheckSave: %v", err)
	}

	path := singleReportPath(t, dir, ".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(data), "{}") {
		t.Fatalf("unexpected YAML report: %q", data)
	}
}

func TestFullCheckSaveRejectsInvalidFormat(t *testing.T) {
	preserveFullCheckOutputConfig(t)
	config.Get().All.Format = "toml"
	config.Get().All.Prefix = filepath.Join(t.TempDir(), "report-")
	config.Get().All.TsFormat = "20060102T150405.000000000"

	err := fullCheckSave(&FullCheckDto{})
	if !errors.Is(err, ErrFullCheckInvalidOutputFormat) {
		t.Fatalf("got %v, want %v", err, ErrFullCheckInvalidOutputFormat)
	}
}

func singleReportPath(t *testing.T, dir, suffix string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var matches []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), suffix) {
			matches = append(matches, entry.Name())
		}
	}
	if len(matches) != 1 {
		t.Fatalf("got %d report files in %s, want 1", len(matches), dir)
	}
	return filepath.Join(dir, matches[0])
}
