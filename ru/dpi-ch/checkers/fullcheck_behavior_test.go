package checkers

import (
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/inetlookup"
	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/inetutil"
)

func TestFullCheckCidrwhitelistDto(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code string
	}{
		{name: "not detected", err: nil, code: "NOT_DETECTED"},
		{name: "detected", err: ErrCidrWhitelistDetected, code: "DETECTED"},
		{name: "no internet", err: ErrCidrWhitelistNoInetAccess, code: "NO_INTERNET_ACCESS"},
		{name: "internal error", err: errors.New("failure"), code: "INTERNAL_ERR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fullCheckCidrwhitelistDto(tt.err)
			if got.Status.Code != tt.code {
				t.Fatalf("got code %q, want %q", got.Status.Code, tt.code)
			}
		})
	}
}

func TestFullCheckPrettyDnsVerdictMapsAllStatuses(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want []FullCheckStatusDto
	}{
		{name: "provider hijacking", err: ErrDnsProviderHijacking, want: []FullCheckStatusDto{{Msg: "Provider hijacking", Code: "PROVIDER_HIJACKING"}}},
		{name: "response spoofing", err: ErrDnsResolveSpoofing, want: []FullCheckStatusDto{{Msg: "Response spoofing", Code: "RESPONSE_SPOOFING"}}},
		{name: "nxdomain spoofing", err: ErrDnsNxdomainSpoofing, want: []FullCheckStatusDto{{Msg: "NXDOMAIN spoofing", Code: "NXDOMAIN_SPOOFING"}}},
		{name: "bootstrap spoofing", err: ErrDnsDohBootstrapSpoofing, want: []FullCheckStatusDto{{Msg: "Bootstrap spoofing", Code: "BOOTSTRAP_SPOOFING"}}},
		{name: "empty bootstrap", err: ErrDnsDohBootstrapEmpty, want: []FullCheckStatusDto{{Msg: "Empty bootstrap", Code: "EMPTY_BOOTSTRAP"}}},
		{name: "insecure https", err: ErrDnsDohInsecure, want: []FullCheckStatusDto{{Msg: "Invalid https certificate", Code: "INVALID_HTTPS_CERT"}}},
		{name: "non-2xx alone", err: ErrDnsDohNon2xxResp, want: []FullCheckStatusDto{{Msg: "Ok", Code: "OK"}}},
		{name: "non-2xx with skip", err: errors.Join(ErrDnsDohNon2xxResp, ErrDnsSkip), want: []FullCheckStatusDto{{Msg: "Non-2xx response", Code: "NON_2XX_RESP"}, {Msg: "Skip", Code: "SKIP"}}},
		{name: "skip", err: ErrDnsSkip, want: []FullCheckStatusDto{{Msg: "Skip", Code: "SKIP"}}},
		{name: "inetutil error", err: inetutil.ErrTcpConnTimeout, want: []FullCheckStatusDto{{Msg: inetutil.ErrTcpConnTimeout.Error(), Code: "INETUTIL_ERR"}}},
		{name: "lookup error", err: &net.DNSError{Err: "not found"}, want: []FullCheckStatusDto{{Msg: "Lookup error", Code: "LOOKUP_ERR"}}},
		{name: "internal error", err: errors.New("failure"), want: []FullCheckStatusDto{{Msg: "Internal error", Code: "INTERNAL_ERR"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fullCheckPrettyDnsVerdict(tt.err)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestFullCheckPrettyDnsVerdict(t *testing.T) {
	if got := fullCheckPrettyDnsVerdict(nil); !slices.Equal(got, []FullCheckStatusDto{{Msg: "Ok", Code: "OK"}}) {
		t.Fatalf("nil verdict got %+v", got)
	}

	err := errors.Join(ErrDnsProviderHijacking, ErrDnsResolveSpoofing, ErrDnsNxdomainSpoofing)
	got := fullCheckPrettyDnsVerdict(err)
	want := []FullCheckStatusDto{
		{Msg: "Provider hijacking", Code: "PROVIDER_HIJACKING"},
		{Msg: "Response spoofing", Code: "RESPONSE_SPOOFING"},
		{Msg: "NXDOMAIN spoofing", Code: "NXDOMAIN_SPOOFING"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestFullCheckDnsReportDtoGroupsProviders(t *testing.T) {
	got := fullCheckDnsReportDto([]DnsVerdict{
		{Provider: "resolver-a", Verdict: nil},
		{Provider: "resolver-b", Verdict: ErrDnsSkip},
	})

	if got.Status.Code != "OK" {
		t.Fatalf("got status %q, want OK", got.Status.Code)
	}
	if !slices.Equal(got.Providers["resolver-a"], []FullCheckStatusDto{{Msg: "Ok", Code: "OK"}}) {
		t.Fatalf("unexpected resolver-a result: %+v", got.Providers["resolver-a"])
	}
	if !slices.Equal(got.Providers["resolver-b"], []FullCheckStatusDto{{Msg: "Skip", Code: "SKIP"}}) {
		t.Fatalf("unexpected resolver-b result: %+v", got.Providers["resolver-b"])
	}
}

func TestFullCheckWhoamiDto(t *testing.T) {
	r := WhoamiResult{
		Ip:       "192.0.2.10",
		Subnet:   "192.0.2.0/24",
		Asn:      "AS64500",
		Org:      "Example",
		Location: "DE",
		Ttlb:     1234 * time.Millisecond,
	}
	got := fullCheckWhoamiDto(r, nil)
	want := FullCheckWhoamiDto{
		Status:   FullCheckStatusDto{Msg: "Ok", Code: "OK"},
		Ip:       "192.0.2.10",
		Subnet:   "192.0.2.0/24",
		Asn:      "AS64500",
		Org:      "Example",
		Location: "DE",
		TtlbMs:   1234,
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	err := errors.New("lookup failed")
	got = fullCheckWhoamiDto(WhoamiResult{}, err)
	if got.Status != (FullCheckStatusDto{Msg: err.Error(), Code: "ERR"}) {
		t.Fatalf("got status %+v, want error status", got.Status)
	}
}

func TestFullCheckDnsLeakDtoSortsAndDeduplicates(t *testing.T) {
	outs := []DnsLeakWithIpinfoOut{
		{Items: []inetlookup.IpInfoStrings{
			{Ip: "192.0.2.20"},
			{Ip: "192.0.2.10"},
		}},
		{Items: []inetlookup.IpInfoStrings{
			{Ip: "192.0.2.20"},
			{Ip: "192.0.2.30"},
		}},
	}

	got := fullCheckDnsLeakDto(outs)
	want := []inetlookup.IpInfoStrings{
		{Ip: "192.0.2.10"},
		{Ip: "192.0.2.20"},
		{Ip: "192.0.2.30"},
	}
	if !slices.Equal(got.Items, want) {
		t.Fatalf("got %+v, want %+v", got.Items, want)
	}
	if got.Status.Code != "OK" {
		t.Fatalf("got status %q, want OK", got.Status.Code)
	}
}

func TestFullCheckDnsLeakDtoPropagatesError(t *testing.T) {
	errWant := errors.New("lookup failed")
	got := fullCheckDnsLeakDto([]DnsLeakWithIpinfoOut{{Err: errWant}})
	if got.Status.Code != "ERR" {
		t.Fatalf("got status %q, want ERR", got.Status.Code)
	}
	if got.Status.Msg != errWant.Error() {
		t.Fatalf("got message %q, want %q", got.Status.Msg, errWant.Error())
	}
}
