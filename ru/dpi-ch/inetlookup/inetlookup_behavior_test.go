package inetlookup

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestGeoLiteCsvIpInfoUsesMostSpecificPrefixes(t *testing.T) {
	lookup := newBehaviorGeoLite(t)
	ip := netip.MustParseAddr("10.1.0.42")

	got := lookup.IpInfo(ip)
	want := IpInfo{
		Ip:         ip,
		Asn:        64501,
		Subnet:     netip.MustParsePrefix("10.1.0.0/16"),
		Org:        "Specific Example",
		CountryIso: "DE",
	}

	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestGeoLiteCsvIpInfoReturnsDefaultsForUnknownIp(t *testing.T) {
	lookup := newBehaviorGeoLite(t)
	ip := netip.MustParseAddr("192.0.2.42")

	got := lookup.IpInfo(ip)
	want := IpInfo{
		Ip:     ip,
		Subnet: netip.MustParsePrefix("0.0.0.0/0"),
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	ipv6 := netip.MustParseAddr("2001:db8::42")
	got = lookup.IpInfo(ipv6)
	want = IpInfo{
		Ip:     ipv6,
		Subnet: netip.MustParsePrefix("0.0.0.0/0"),
	}
	if got != want {
		t.Fatalf("IPv6 got %+v, want %+v", got, want)
	}
}

func TestGeoLiteCsvQueriesNormalizeCase(t *testing.T) {
	lookup := newBehaviorGeoLite(t)

	country := lookup.Cidrs(CidrsOpt{CountryIsoCodes: []string{"dE"}}).Prefixes()
	wantCountry := []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}
	if !slices.Equal(country, wantCountry) {
		t.Fatalf("country query got %v, want %v", country, wantCountry)
	}

	org := lookup.Cidrs(CidrsOpt{OrgTerms: []string{"SPECIFIC"}}).Prefixes()
	wantOrg := []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}
	if !slices.Equal(org, wantOrg) {
		t.Fatalf("org query got %v, want %v", org, wantOrg)
	}
}

func TestGeoLiteCsvQueriesByIpAsnAndOrg(t *testing.T) {
	lookup := newBehaviorGeoLite(t)

	ip := netip.MustParseAddr("10.1.0.42")
	asns := lookup.Asns(AsnsOpt{Ips: []netip.Addr{ip}})
	if !slices.Equal(asns, []int32{64500, 64501}) {
		t.Fatalf("got ASNs %v, want [64500 64501]", asns)
	}

	terms := lookup.OrgTerms(OrgTermsOpt{Ips: []netip.Addr{ip}})
	if !slices.Equal(terms, []string{"Broad Example", "Specific Example"}) {
		t.Fatalf("got org terms %v, want [Broad Example, Specific Example]", terms)
	}
}

func TestGeoLiteCsvCidrsByAsnAndOrg(t *testing.T) {
	lookup := newBehaviorGeoLite(t)

	asn := lookup.Cidrs(CidrsOpt{Asns: []int32{64501}}).Prefixes()
	if !slices.Equal(asn, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}) {
		t.Fatalf("ASN query got %v", asn)
	}

	org := lookup.Cidrs(CidrsOpt{OrgTerms: []string{"specific example"}}).Prefixes()
	if !slices.Equal(org, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}) {
		t.Fatalf("organization query got %v", org)
	}
}

func TestGeoLiteCsvEmptyQueryReturnsEmptySet(t *testing.T) {
	lookup := newBehaviorGeoLite(t)
	if got := lookup.Cidrs(CidrsOpt{}).Prefixes(); len(got) != 0 {
		t.Fatalf("got %v, want empty set", got)
	}
}

func newBehaviorGeoLite(t *testing.T) InetLookup {
	t.Helper()

	dir := t.TempDir()
	locations := filepath.Join(dir, "locations.csv")
	countries := filepath.Join(dir, "countries.csv")
	asns := filepath.Join(dir, "asns.csv")

	writeBehaviorFile(t, locations, "geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union\n100,en,NA,North America,US,United States,0\n200,en,EU,Europe,DE,Germany,1\n")
	writeBehaviorFile(t, countries, "network,geoname_id_registered,geoname_id_represented,geoname_id_assigned\n10.0.0.0/8,100,0,0\n10.1.0.0/16,200,0,0\n")
	writeBehaviorFile(t, asns, "network,autonomous_system_number,autonomous_system_organization\n10.0.0.0/8,64500,Broad Example\n10.1.0.0/16,64501,Specific Example\n")

	return NewGeoliteCsv(GeoliteCsvOpt{
		GeonameidCountryPath: locations,
		CidrCountryPath:      countries,
		CidrAsPath:           asns,
	})
}

func writeBehaviorFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
