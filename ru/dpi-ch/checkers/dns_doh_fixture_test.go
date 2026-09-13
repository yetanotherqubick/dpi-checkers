package checkers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/config"
)

func preserveDnsDohFixtureConfig(t *testing.T) {
	t.Helper()
	oldResolve := config.Get().Checkers.Dns.Resolve.PlainOpt
	oldGeoLite := config.Get().InetlookupGeolitecsv
	t.Cleanup(func() {
		config.Get().Checkers.Dns.Resolve.PlainOpt = oldResolve
		config.Get().InetlookupGeolitecsv = oldGeoLite
	})
	configureWhoamiTestLookup(t)
	config.Get().Checkers.Dns.Resolve.PlainOpt.Timeout = time.Second
}

func TestDnsDohBootstrapAcceptsMatchingLocalAddress(t *testing.T) {
	preserveDnsDohFixtureConfig(t)

	got, err := dnsDohBootstrap(context.Background(), "localhost", `subnet("127.0.0.0/8")`)
	if err != nil {
		t.Fatalf("dnsDohBootstrap: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("got no IPv4 bootstrap addresses")
	}
	for _, ip := range got {
		if !ip.Is4() || !ip.IsLoopback() {
			t.Fatalf("got unexpected bootstrap address %v", ip)
		}
	}
}

func TestDnsDohBootstrapDetectsAddressOutsideFilter(t *testing.T) {
	preserveDnsDohFixtureConfig(t)

	_, err := dnsDohBootstrap(context.Background(), "localhost", `subnet("192.0.2.0/24")`)
	if !errors.Is(err, ErrDnsDohBootstrapSpoofing) {
		t.Fatalf("got %v, want %v", err, ErrDnsDohBootstrapSpoofing)
	}
}

func TestDnsDohBootstrapPropagatesLookupError(t *testing.T) {
	preserveDnsDohFixtureConfig(t)

	_, err := dnsDohBootstrap(context.Background(), "does-not-exist.invalid", "")
	if err == nil {
		t.Fatal("expected lookup error")
	}
}
