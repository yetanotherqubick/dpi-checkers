package checkers

import (
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDnsErrorsPreservePriority(t *testing.T) {
	err := errors.Join(
		ErrDnsSkip,
		ErrDnsResolveSpoofing,
		ErrDnsProviderHijacking,
		ErrDnsResolveSpoofing,
	)

	got := DnsErrors(err)
	want := []error{
		ErrDnsProviderHijacking,
		ErrDnsResolveSpoofing,
		ErrDnsSkip,
	}

	if len(got) != len(want) {
		t.Fatalf("got %d errors, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if !errors.Is(got[i], want[i]) {
			t.Fatalf("got error %v at index %d, want %v", got[i], i, want[i])
		}
	}
}

func TestDnsVerdict(t *testing.T) {
	networkErr := errors.New("network")
	tests := []struct {
		name string
		errs []error
		want error
	}{
		{name: "empty", errs: nil, want: nil},
		{name: "ordinary error", errs: []error{networkErr}, want: networkErr},
		{name: "censorship error wins", errs: []error{networkErr, ErrDnsNxdomainSpoofing}, want: ErrDnsNxdomainSpoofing},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dnsVerdict(tt.errs)
			if tt.want == nil {
				if got != nil {
					t.Fatalf("got %v, want nil", got)
				}
				return
			}
			if !errors.Is(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDnsVerdictsAggregateMatrixErrors(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		matrix := []DnsPlainAnswer{{Err: ErrDnsResolveSpoofing}}
		got := dnsPlainVerdict(matrix, ErrDnsProviderHijacking)
		if !errors.Is(got, ErrDnsProviderHijacking) || !errors.Is(got, ErrDnsResolveSpoofing) {
			t.Fatalf("got %v, want both provider hijacking and response spoofing", got)
		}
	})

	t.Run("doh", func(t *testing.T) {
		matrix := []DnsDohAnswer{{
			BootstrapErr: ErrDnsDohBootstrapSpoofing,
			Items:        []DnsDohAnswerItem{{Err: ErrDnsDohInsecure}},
		}}
		got := dnsDohVerdict(matrix)
		if !errors.Is(got, ErrDnsDohBootstrapSpoofing) || !errors.Is(got, ErrDnsDohInsecure) {
			t.Fatalf("got %v, want both bootstrap spoofing and insecure TLS", got)
		}
	})
}

func TestDnsPrepareA(t *testing.T) {
	a := mustDnsQuestion(t, "example.com")
	b := mustDnsQuestion(t, "example.com.")

	if a.Name != b.Name || a.Type != b.Type || a.Class != b.Class {
		t.Fatalf("trailing-dot variants differ: %v vs %v", a, b)
	}
	if a.Name.String() != "example.com." {
		t.Fatalf("got name %q, want %q", a.Name.String(), "example.com.")
	}
	if a.Type != dnsmessage.TypeA {
		t.Fatalf("got type %v, want A", a.Type)
	}
	if a.Class != dnsmessage.ClassINET {
		t.Fatalf("got class %v, want INET", a.Class)
	}
}

func mustDnsQuestion(t *testing.T, target string) dnsmessage.Question {
	t.Helper()

	raw, err := dnsPrepareA(target)
	if err != nil {
		t.Fatalf("dnsPrepareA(%q): %v", target, err)
	}

	var p dnsmessage.Parser
	h, err := p.Start(raw)
	if err != nil {
		t.Fatalf("parse header: %v", err)
	}
	if !h.RecursionDesired {
		t.Fatal("recursion-desired flag is not set")
	}

	q, err := p.Question()
	if err != nil {
		t.Fatalf("parse question: %v", err)
	}
	return q
}

func TestDnsPlainVerdictWithNoErrors(t *testing.T) {
	matrix := []DnsPlainAnswer{{
		Target:       DnsTarget{Hostname: "example.com"},
		ResolverAddr: "192.0.2.1:53",
		Items:        []netip.Addr{netip.MustParseAddr("192.0.2.10")},
	}}

	if got := dnsPlainVerdict(matrix, nil); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}
