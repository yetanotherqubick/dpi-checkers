package checkers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/config"
)

func TestFullCheckReportsDnsResponseSpoofing(t *testing.T) {
	old := *config.Get()
	t.Cleanup(func() { *config.Get() = old })
	configureWhoamiTestLookup(t)

	dnsAddr := startTestDNSServer(t, testDNSA)

	config.Get().Checkers.Dns.Leak.Times = 0
	config.Get().Checkers.Dns.Resolve.PlainOpt.Workers = 1
	config.Get().Checkers.Dns.Resolve.DohOpt.Workers = 1
	config.Get().Checkers.Dns.Resolve.Providers = []struct {
		Name  string `mapstructure:"name"`
		Plain struct {
			Filter string   `mapstructure:"filter"`
			Hosts  []string `mapstructure:"hosts"`
		} `mapstructure:"plain"`
		DoH struct {
			Filter string   `mapstructure:"filter"`
			Hosts  []string `mapstructure:"hosts"`
		} `mapstructure:"doh"`
	}{
		{
			Name: "local",
			Plain: struct {
				Filter string   `mapstructure:"filter"`
				Hosts  []string `mapstructure:"hosts"`
			}{Hosts: []string{dnsAddr}},
		},
	}
	config.Get().Checkers.Dns.Resolve.Targets = []struct {
		Host   string `mapstructure:"host"`
		Filter string `mapstructure:"filter"`
	}{{Host: "example.test", Filter: `subnet("198.51.100.0/24")`}}

	outDir := t.TempDir()
	config.Get().All.Format = "json"
	config.Get().All.TsFormat = "20060102T150405.000000000"
	config.Get().All.Prefix = filepath.Join(outDir, "report-")
	config.Get().All.Checkers = []string{"dns"}
	config.Get().Checkers.Dns.Resolve.PlainOpt.Timeout = time.Second
	config.Get().Checkers.Dns.Resolve.DohOpt.Timeout = time.Second

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
		t.Fatalf("read report: %v", err)
	}
	var report FullCheckDto
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	got := report.Dns.Plain.Providers["local"]
	if len(got) != 1 || got[0].Code != "RESPONSE_SPOOFING" {
		t.Fatalf("got DNS plain verdict %+v, want RESPONSE_SPOOFING", got)
	}
}
