package subnetfilter

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/inetlookup"
)

func TestSubnetfilterExpressions(t *testing.T) {
	lookup := newTestGeoLite(t)
	sf := New(lookup)

	tests := []struct {
		name   string
		filter string
		want   []string
	}{
		{
			name:   "country is case insensitive",
			filter: `country("us")`,
			want:   []string{"10.0.0.0/24"},
		},
		{
			name:   "country accepts multiple codes",
			filter: `country("us", "de")`,
			want:   []string{"10.0.0.0/23"},
		},
		{
			name:   "asn lookup",
			filter: `as(64501)`,
			want:   []string{"10.0.1.0/24"},
		},
		{
			name:   "asn lookup by ip",
			filter: `as("10.0.1.42")`,
			want:   []string{"10.0.1.0/24"},
		},
		{
			name:   "organization lookup",
			filter: `org("cloudflare")`,
			want:   []string{"10.0.2.0/24"},
		},
		{
			name:   "organization lookup by asn",
			filter: `org(64502)`,
			want:   []string{"10.0.2.0/24"},
		},
		{
			name:   "organization lookup by ip",
			filter: `org("10.0.2.42")`,
			want:   []string{"10.0.2.0/24"},
		},
		{
			name:   "intersection",
			filter: `org("cloudflare") && country("ca")`,
			want:   []string{"10.0.2.0/24"},
		},
		{
			name:   "disjoint intersection",
			filter: `country("us") && country("de")`,
			want:   nil,
		},
		{
			name:   "union",
			filter: `country("us") || country("de")`,
			want:   []string{"10.0.0.0/23"},
		},
		{
			name:   "explicit precedence",
			filter: `(country("us") || country("de")) && country("de")`,
			want:   []string{"10.0.1.0/24"},
		},
		{
			name:   "subnet accepts address",
			filter: `subnet("10.0.0.42")`,
			want:   []string{"10.0.0.0/24"},
		},
		{
			name:   "subnet accepts cidr",
			filter: `subnet("192.0.2.0/24")`,
			want:   []string{"192.0.2.0/24"},
		},
		{
			name:   "subnet accepts multiple values",
			filter: `subnet("10.0.0.42", "10.0.1.0/24")`,
			want:   []string{"10.0.0.0/23"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program, err := sf.CompileFilter(tt.filter)
			if err != nil {
				t.Fatalf("compile %q: %v", tt.filter, err)
			}

			set, err := sf.RunFilter(program)
			if err != nil {
				t.Fatalf("run %q: %v", tt.filter, err)
			}

			got := make([]string, 0, len(set.Prefixes()))
			for _, prefix := range set.Prefixes() {
				got = append(got, prefix.String())
			}
			slices.Sort(got)

			want := append([]string(nil), tt.want...)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestSubnetfilterCompileFilterRejectsInvalidExpression(t *testing.T) {
	sf := New(newTestGeoLite(t))
	if _, err := sf.CompileFilter(`country("us"`); err == nil {
		t.Fatal("expected invalid filter to fail compilation")
	}
}

func TestExtractHostname(t *testing.T) {
	sf := New(newTestGeoLite(t))

	tests := []struct {
		name   string
		filter string
		want   string
		ok     bool
	}{
		{name: "single host", filter: `host("example.com")`, want: "example.com", ok: true},
		{name: "multiple hosts", filter: `host("example.com", "example.net")`, ok: false},
		{name: "other function", filter: `country("us")`, ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program, err := sf.CompileFilter(tt.filter)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got, ok := sf.ExtractHostname(program)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("got (%q, %v), want (%q, %v)", got, ok, tt.want, tt.ok)
			}
		})
	}

	if got, ok := sf.ExtractHostname(nil); got != "" || ok {
		t.Fatalf("nil program returned (%q, %v), want (\"\", false)", got, ok)
	}
}

func newTestGeoLite(t *testing.T) inetlookup.InetLookup {
	t.Helper()

	dir := t.TempDir()
	locations := filepath.Join(dir, "locations.csv")
	countries := filepath.Join(dir, "countries.csv")
	asns := filepath.Join(dir, "asns.csv")

	writeTestFile(t, locations, "geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union\n100,en,NA,North America,US,United States,0\n200,en,EU,Europe,DE,Germany,1\n300,en,NA,North America,CA,Canada,0\n")
	writeTestFile(t, countries, "network,geoname_id_registered,geoname_id_represented,geoname_id_assigned\n10.0.0.0/24,100,0,0\n10.0.1.0/24,200,0,0\n10.0.2.0/24,300,0,0\n")
	writeTestFile(t, asns, "network,autonomous_system_number,autonomous_system_organization\n10.0.0.0/24,64500,Example US\n10.0.1.0/24,64501,Example DE\n10.0.2.0/24,64502,Cloudflare Example\n")

	return inetlookup.NewGeoliteCsv(inetlookup.GeoliteCsvOpt{
		GeonameidCountryPath: locations,
		CidrCountryPath:      countries,
		CidrAsPath:           asns,
	})
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
