package webhostfarm

import (
	"net/netip"
	"slices"
	"testing"

	"go4.org/netipx"
)

func TestIpRangeTotal(t *testing.T) {
	p := netip.MustParsePrefix("192.168.0.0/16")
	r := netipx.RangeOfPrefix(p)
	got := iprangeTotal(r)
	want := uint64(1 << 16)
	if got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestIpSetTotalCountsIPv4Ranges(t *testing.T) {
	var b netipx.IPSetBuilder
	b.AddPrefix(netip.MustParsePrefix("192.168.0.0/16"))
	b.AddPrefix(netip.MustParsePrefix("192.169.1.0/24"))
	s, _ := b.IPSet()

	got := ipsetTotal(s)
	want := uint64((1 << 16) + (1 << 8))
	if got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestRandomIpsIterEnumeratesSmallSetWithoutDuplicates(t *testing.T) {
	var b netipx.IPSetBuilder
	b.AddPrefix(netip.MustParsePrefix("192.0.2.0/30"))
	b.AddPrefix(netip.MustParsePrefix("198.51.100.0/31"))
	s, _ := b.IPSet()

	var got []netip.Addr
	for ip := range randomIpsIter(s) {
		got = append(got, ip)
	}

	want := []netip.Addr{
		netip.MustParseAddr("192.0.2.0"),
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.3"),
		netip.MustParseAddr("198.51.100.0"),
		netip.MustParseAddr("198.51.100.1"),
	}
	slices.SortFunc(got, func(a, b netip.Addr) int { return a.Compare(b) })
	slices.SortFunc(want, func(a, b netip.Addr) int { return a.Compare(b) })

	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestRandomIpsIterIgnoresIPv6(t *testing.T) {
	var b netipx.IPSetBuilder
	b.AddPrefix(netip.MustParsePrefix("2001:db8::/126"))
	s, _ := b.IPSet()

	count := 0
	for range randomIpsIter(s) {
		count++
	}
	if count != 0 {
		t.Fatalf("got %d IPv6 addresses, want 0", count)
	}
}

func TestRandomIpsIterEmptySet(t *testing.T) {
	var b netipx.IPSetBuilder
	s, _ := b.IPSet()
	for range randomIpsIter(s) {
		t.Fatal("empty set produced an address")
	}
}

func TestIPv4IntegerRoundTrip(t *testing.T) {
	tests := []netip.Addr{
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("255.255.255.255"),
	}
	for _, want := range tests {
		got := u32ip4(ip4u32(want))
		if got != want {
			t.Errorf("round trip %v -> %v", want, got)
		}
	}
}
