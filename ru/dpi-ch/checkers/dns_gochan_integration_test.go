package checkers

import (
	"context"
	"testing"
	"time"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/config"
)

func TestDnsPlainGochanUsesConfiguredLocalResolver(t *testing.T) {
	old := *config.Get()
	t.Cleanup(func() { *config.Get() = old })
	configureWhoamiTestLookup(t)

	addr := startTestDNSServer(t, testDNSA)
	config.Get().Checkers.Dns.Resolve.PlainOpt.Workers = 1
	config.Get().Checkers.Dns.Resolve.PlainOpt.Timeout = 2 * time.Second
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
			}{Hosts: []string{addr}},
		},
	}
	config.Get().Checkers.Dns.Resolve.Targets = []struct {
		Host   string `mapstructure:"host"`
		Filter string `mapstructure:"filter"`
	}{{Host: "example.test", Filter: `subnet("192.0.2.0/24")`}}

	got := <-DnsPlainGochan(context.Background())
	if got.Provider != "local" {
		t.Fatalf("got provider %q, want local", got.Provider)
	}
	if got.Verdict != nil {
		t.Fatalf("got verdict %v, want nil", got.Verdict)
	}
}
