package checkers

import (
	"context"
	"testing"
	"time"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/config"
)

func TestDnsLeakGochanPropagatesLookupFailure(t *testing.T) {
	old := config.Get().Checkers.Dns.Leak
	t.Cleanup(func() { config.Get().Checkers.Dns.Leak = old })
	config.Get().Checkers.Dns.Leak.Timeout = 100 * time.Millisecond
	config.Get().Checkers.Dns.Leak.Times = 2
	config.Get().Checkers.Dns.Leak.Workers = 2
	config.Get().Checkers.Dns.Leak.ParentDomain = "127.0.0.1:1"
	config.Get().Checkers.Dns.Leak.LabelLen = 4
	config.Get().Checkers.Dns.Leak.LabelAlpha = "ab"

	count := 0
	for out := range DnsLeakGochan(context.Background()) {
		count++
		if out.Err == nil {
			t.Fatal("got nil error, want lookup failure")
		}
	}
	if count != 2 {
		t.Fatalf("got %d results, want 2", count)
	}
}

func TestDnsLeakGochanCancellationProducesNoResults(t *testing.T) {
	old := config.Get().Checkers.Dns.Leak
	t.Cleanup(func() { config.Get().Checkers.Dns.Leak = old })
	config.Get().Checkers.Dns.Leak.Timeout = time.Second
	config.Get().Checkers.Dns.Leak.Times = 100
	config.Get().Checkers.Dns.Leak.Workers = 2
	config.Get().Checkers.Dns.Leak.ParentDomain = "127.0.0.1:1"
	config.Get().Checkers.Dns.Leak.LabelLen = 4
	config.Get().Checkers.Dns.Leak.LabelAlpha = "ab"

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	count := 0
	for range DnsLeakGochan(ctx) {
		count++
	}
	if count != 0 {
		t.Fatalf("got %d results, want 0", count)
	}
}
