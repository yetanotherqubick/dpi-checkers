package checkers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/config"
)

func TestMain(m *testing.M) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		os.Exit(1)
	}
	base := filepath.Join(filepath.Dir(file), "../inetlookup/testdata/geolite2_csv")
	cfg := &config.Get().InetlookupGeolitecsv
	cfg.CidrAs = filepath.Join(base, "cidr2as_ipv4.csv")
	cfg.CidrCountry = filepath.Join(base, "cidr2countryIso_ipv4.csv")
	cfg.GeonameidCountry = filepath.Join(base, "geonameId2country_en.csv")
	os.Exit(m.Run())
}

func preserveWhoamiConfig(t *testing.T) {
	t.Helper()

	oldWhoami := config.Get().Checkers.Whoami
	oldLookup := config.Get().InetLookup
	oldGeoLite := config.Get().InetlookupGeolitecsv
	t.Cleanup(func() {
		config.Get().Checkers.Whoami = oldWhoami
		config.Get().InetLookup = oldLookup
		config.Get().InetlookupGeolitecsv = oldGeoLite
	})
}

func configureWhoamiTestLookup(t *testing.T) {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	base := filepath.Join(filepath.Dir(file), "../inetlookup/testdata/geolite2_csv")
	cfg := &config.Get().InetlookupGeolitecsv
	cfg.CidrAs = filepath.Join(base, "cidr2as_ipv4.csv")
	cfg.CidrCountry = filepath.Join(base, "cidr2countryIso_ipv4.csv")
	cfg.GeonameidCountry = filepath.Join(base, "geonameId2country_en.csv")
}

func TestWhoamiUsesYandex(t *testing.T) {
	preserveWhoamiConfig(t)
	configureWhoamiTestLookup(t)

	const expectedIP = "31.44.8.1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ip" {
			t.Fatalf("got path %q, want /ip", r.URL.Path)
		}
		if err := json.NewEncoder(w).Encode(expectedIP); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	config.Get().Checkers.Whoami.Timeout = time.Second
	config.Get().InetLookup.YandexApiUrl = srv.URL + "/"
	config.Get().InetLookup.RipeApiUrl = "http://127.0.0.1:1/"

	got, err := Whoami(t.Context())
	if err != nil {
		t.Fatalf("Whoami: %v", err)
	}

	if got.Ip != expectedIP {
		t.Fatalf("got IP %q, want %q", got.Ip, expectedIP)
	}
	if got.Asn != "AS200351" {
		t.Fatalf("got ASN %q, want AS200351", got.Asn)
	}
	if got.Org != "Yandex.Cloud LLC" {
		t.Fatalf("got org %q, want Yandex.Cloud LLC", got.Org)
	}
	if got.Location != "RU" {
		t.Fatalf("got location %q, want RU", got.Location)
	}
	if got.Subnet != "31.44.8.0/24" {
		t.Fatalf("got subnet %q, want 31.44.8.0/24", got.Subnet)
	}
	if got.Ttlb <= 0 {
		t.Fatal("expected positive time-to-last-byte")
	}
}

func TestWhoamiFallsBackToRipe(t *testing.T) {
	preserveWhoamiConfig(t)
	configureWhoamiTestLookup(t)

	const expectedIP = "31.44.8.1"
	var yandexCalls, ripeCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ip":
			yandexCalls++
			_, _ = w.Write([]byte("not json"))
		case "/whats-my-ip/data.json":
			ripeCalls++
			_, _ = w.Write([]byte(`{"data":{"ip":"` + expectedIP + `"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	config.Get().Checkers.Whoami.Timeout = time.Second
	config.Get().InetLookup.YandexApiUrl = srv.URL + "/"
	config.Get().InetLookup.RipeApiUrl = srv.URL + "/"

	got, err := Whoami(t.Context())
	if err != nil {
		t.Fatalf("Whoami: %v", err)
	}
	if got.Ip != expectedIP {
		t.Fatalf("got IP %q, want %q", got.Ip, expectedIP)
	}
	if yandexCalls != 1 || ripeCalls != 1 {
		t.Fatalf("got yandex calls %d, ripe calls %d, want 1 each", yandexCalls, ripeCalls)
	}
}
