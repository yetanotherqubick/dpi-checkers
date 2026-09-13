package checkers

import (
	"context"
	"slices"
	"testing"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/config"
)

func preserveDnsResolveWrapperConfig(t *testing.T) {
	t.Helper()
	old := config.Get().Checkers.Dns.Resolve
	t.Cleanup(func() {
		config.Get().Checkers.Dns.Resolve = old
	})
}

func TestDnsPlainGochanSkipsProviderWithoutAddresses(t *testing.T) {
	preserveDnsResolveWrapperConfig(t)
	cfg := &config.Get().Checkers.Dns.Resolve
	cfg.PlainOpt.Workers = 1
	cfg.Providers = nil

	cfg.Providers = append(cfg.Providers, struct {
		Name  string `mapstructure:"name"`
		Plain struct {
			Filter string   `mapstructure:"filter"`
			Hosts  []string `mapstructure:"hosts"`
		} `mapstructure:"plain"`
		DoH struct {
			Filter string   `mapstructure:"filter"`
			Hosts  []string `mapstructure:"hosts"`
		} `mapstructure:"doh"`
	}{Name: "empty"})

	got := <-DnsPlainGochan(context.Background())
	if got.Provider != "empty" || got.Verdict != ErrDnsSkip {
		t.Fatalf("got %+v, want empty provider skipped", got)
	}
}

func TestDnsDohGochanSkipsProviderWithoutHosts(t *testing.T) {
	preserveDnsResolveWrapperConfig(t)
	cfg := &config.Get().Checkers.Dns.Resolve
	cfg.DohOpt.Workers = 1
	cfg.Providers = nil

	cfg.Providers = append(cfg.Providers, struct {
		Name  string `mapstructure:"name"`
		Plain struct {
			Filter string   `mapstructure:"filter"`
			Hosts  []string `mapstructure:"hosts"`
		} `mapstructure:"plain"`
		DoH struct {
			Filter string   `mapstructure:"filter"`
			Hosts  []string `mapstructure:"hosts"`
		} `mapstructure:"doh"`
	}{Name: "empty"})

	got := <-DnsDohGochan(context.Background())
	if got.Provider != "empty" || got.Verdict != ErrDnsSkip {
		t.Fatalf("got %+v, want empty provider skipped", got)
	}
}

func TestDnsTargetsCopiesConfiguredTargets(t *testing.T) {
	preserveDnsResolveWrapperConfig(t)
	cfg := &config.Get().Checkers.Dns.Resolve
	cfg.Targets = nil

	cfg.Targets = append(cfg.Targets,
		struct {
			Host   string `mapstructure:"host"`
			Filter string `mapstructure:"filter"`
		}{Host: "one.example", Filter: `country("US")`},
		struct {
			Host   string `mapstructure:"host"`
			Filter string `mapstructure:"filter"`
		}{Host: "two.example", Filter: `country("DE")`},
	)

	got := dnsTargets()
	want := []DnsTarget{
		{Hostname: "one.example", Filter: `country("US")`},
		{Hostname: "two.example", Filter: `country("DE")`},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
