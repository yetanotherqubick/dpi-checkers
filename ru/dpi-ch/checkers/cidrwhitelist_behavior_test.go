package checkers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/config"
)

func preserveCidrWhitelistConfig(t *testing.T) {
	t.Helper()
	old := config.Get().Checkers.CidrWhitelist
	t.Cleanup(func() {
		config.Get().Checkers.CidrWhitelist = old
	})
}

func TestCidrWhitelistRegularAccessWins(t *testing.T) {
	preserveCidrWhitelistConfig(t)

	regularURL, closeServer := successfulHeadServer(t)
	defer closeServer()
	whitelistedURL := closedHTTPServerURL(t)

	config.Get().Checkers.CidrWhitelist.Timeout = time.Second
	config.Get().Checkers.CidrWhitelist.Regular = []string{regularURL}
	config.Get().Checkers.CidrWhitelist.Whitelisted = []string{whitelistedURL}

	if got := CidrWhitelist(context.Background()); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

func TestCidrWhitelistDetectsWhitelistOnlyAccess(t *testing.T) {
	preserveCidrWhitelistConfig(t)

	regularURL := closedHTTPServerURL(t)
	whitelistedURL, closeServer := successfulHeadServer(t)
	defer closeServer()

	config.Get().Checkers.CidrWhitelist.Timeout = time.Second
	config.Get().Checkers.CidrWhitelist.Regular = []string{regularURL}
	config.Get().Checkers.CidrWhitelist.Whitelisted = []string{whitelistedURL}

	if got := CidrWhitelist(context.Background()); got != ErrCidrWhitelistDetected {
		t.Fatalf("got %v, want %v", got, ErrCidrWhitelistDetected)
	}
}

func TestCidrWhitelistReportsNoInternetAccess(t *testing.T) {
	preserveCidrWhitelistConfig(t)

	config.Get().Checkers.CidrWhitelist.Timeout = 100 * time.Millisecond
	config.Get().Checkers.CidrWhitelist.Regular = []string{closedHTTPServerURL(t)}
	config.Get().Checkers.CidrWhitelist.Whitelisted = []string{closedHTTPServerURL(t)}

	if got := CidrWhitelist(context.Background()); got != ErrCidrWhitelistNoInetAccess {
		t.Fatalf("got %v, want %v", got, ErrCidrWhitelistNoInetAccess)
	}
}

func TestCidrWhitelistWithNoUrlsReportsNoInternetAccess(t *testing.T) {
	preserveCidrWhitelistConfig(t)

	config.Get().Checkers.CidrWhitelist.Timeout = time.Second
	config.Get().Checkers.CidrWhitelist.Regular = nil
	config.Get().Checkers.CidrWhitelist.Whitelisted = nil

	if got := CidrWhitelist(context.Background()); got != ErrCidrWhitelistNoInetAccess {
		t.Fatalf("got %v, want %v", got, ErrCidrWhitelistNoInetAccess)
	}
}

func successfulHeadServer(t *testing.T) (string, func()) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("got method %s, want HEAD", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	return srv.URL, srv.Close
}

func closedHTTPServerURL(t *testing.T) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	return url
}
