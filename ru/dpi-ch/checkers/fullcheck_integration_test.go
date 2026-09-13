package checkers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/config"
)

func TestFullCheckRunsConfiguredCheckersAgainstLocalFixtures(t *testing.T) {
	old := *config.Get()
	t.Cleanup(func() { *config.Get() = old })
	configureWhoamiTestLookup(t)

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ip":
			_, _ = io.WriteString(w, `"31.44.8.1"`)
		case "/whats-my-ip/data.json":
			_, _ = io.WriteString(w, `{"data":{"ip":"31.44.8.1"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	regular := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("regular fixture got method %s, want HEAD", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer regular.Close()

	config.Get().Checkers.Whoami.Timeout = time.Second
	config.Get().InetLookup.YandexApiUrl = api.URL + "/"
	config.Get().InetLookup.RipeApiUrl = api.URL + "/"

	config.Get().Checkers.CidrWhitelist.Timeout = time.Second
	config.Get().Checkers.CidrWhitelist.Regular = []string{regular.URL}
	config.Get().Checkers.CidrWhitelist.Whitelisted = nil

	outDir := t.TempDir()
	config.Get().All.Format = "json"
	config.Get().All.TsFormat = "20060102T150405.000000000"
	config.Get().All.Prefix = filepath.Join(outDir, "report-")
	config.Get().All.Checkers = []string{"whoami", "cidrwhitelist"}

	for range FullCheckGochan(t.Context()) {
	}

	files, err := filepath.Glob(filepath.Join(outDir, "report-*.json"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d report files, want 1", len(files))
	}

	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var report FullCheckDto
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	if report.Whoami == nil || report.Whoami.Status.Code != "OK" || report.Whoami.Ip != "31.44.8.1" {
		t.Fatalf("unexpected whoami result: %+v", report.Whoami)
	}
	if report.CidrWhitelist == nil || report.CidrWhitelist.Status.Code != "NOT_DETECTED" {
		t.Fatalf("unexpected cidrwhitelist result: %+v", report.CidrWhitelist)
	}
}

func TestFullCheckReportsSaveFailure(t *testing.T) {
	old := *config.Get()
	t.Cleanup(func() { *config.Get() = old })

	dir := t.TempDir()
	config.Get().All.Checkers = nil
	config.Get().All.Format = "invalid"
	config.Get().All.TsFormat = "20060102T150405"
	config.Get().All.Prefix = filepath.Join(dir, "report-")

	var messages []string
	for progress := range FullCheckGochan(t.Context()) {
		messages = append(messages, progress.Msg)
	}

	found := false
	for _, msg := range messages {
		if msg == "error when saving to a file; enable debug and check the logs" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("did not receive save failure progress: %v", messages)
	}

	files, err := filepath.Glob(filepath.Join(dir, "report-*.invalid"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("got report files after save failure: %v", files)
	}
}
