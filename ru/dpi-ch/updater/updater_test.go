package updater

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/config"
)

func preserveUpdaterConfig(t *testing.T) {
	t.Helper()
	old := config.Get().Updater
	t.Cleanup(func() {
		config.Get().Updater = old
	})
}

func TestLocalHashRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "GeoLite2.csv")

	got, err := readLocalHash(path)
	if err != nil {
		t.Fatalf("readLocalHash missing file: %v", err)
	}
	if got != "" {
		t.Fatalf("got %q for missing hash, want empty", got)
	}

	if err := writeLocalHash(path, "abc123"); err != nil {
		t.Fatalf("writeLocalHash: %v", err)
	}
	got, err = readLocalHash(path)
	if err != nil {
		t.Fatalf("readLocalHash: %v", err)
	}
	if got != "abc123" {
		t.Fatalf("got %q, want %q", got, "abc123")
	}
}

func TestTimeToUpdate(t *testing.T) {
	preserveUpdaterConfig(t)
	config.Get().Updater.RootDir = t.TempDir()
	config.Get().Updater.Period = time.Hour

	if got, err := TimeToUpdate("timestamp"); err != nil || !got {
		t.Fatalf("missing timestamp got (%v, %v), want (true, nil)", got, err)
	}

	dst := filepath.Join(config.Get().Updater.RootDir, "timestamp")
	if err := writeUpdateTimestamp(dst); err != nil {
		t.Fatalf("writeUpdateTimestamp: %v", err)
	}
	if got, err := TimeToUpdate("timestamp"); err != nil || got {
		t.Fatalf("fresh timestamp got (%v, %v), want (false, nil)", got, err)
	}

	old := time.Now().Add(-2 * time.Hour).Unix()
	if err := os.WriteFile(dst, []byte(strconv.FormatInt(old, 10)), 0o644); err != nil {
		t.Fatalf("write old timestamp: %v", err)
	}
	if got, err := TimeToUpdate("timestamp"); err != nil || !got {
		t.Fatalf("expired timestamp got (%v, %v), want (true, nil)", got, err)
	}

	if err := os.WriteFile(dst, []byte("not-a-timestamp"), 0o644); err != nil {
		t.Fatalf("write malformed timestamp: %v", err)
	}
	if got, err := TimeToUpdate("timestamp"); err != nil || !got {
		t.Fatalf("malformed timestamp got (%v, %v), want (true, nil)", got, err)
	}
}

func TestDownloadReplacesDestination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("got method %s, want GET", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("new content"))
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "nested", "data.csv")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dst, []byte("old content"), 0o644); err != nil {
		t.Fatalf("write old content: %v", err)
	}

	if err := download(context.Background(), srv.URL, dst); err != nil {
		t.Fatalf("download: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if string(got) != "new content" {
		t.Fatalf("got %q, want %q", got, "new content")
	}
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary download file still exists: %v", err)
	}
}

func TestDownloadRejectsNonSuccessStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "data.csv")
	if err := download(context.Background(), srv.URL, dst); err == nil {
		t.Fatal("expected non-success status to fail")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("destination exists after failed download: %v", err)
	}
}

func TestUpdateUrlsEscapePathAndBranch(t *testing.T) {
	got := attrUrl("owner", "repo", "dir/file.csv", "release branch")
	want := "https://api.github.com/repos/owner/repo/contents/dir%2Ffile.csv?ref=release+branch"
	if got != want {
		t.Fatalf("attrUrl got %q, want %q", got, want)
	}

	got = contentUrl("owner", "repo", "dir/file.csv", "release branch")
	want = "https://raw.githubusercontent.com/owner/repo/refs/heads/release%20branch/dir%2Ffile.csv"
	if got != want {
		t.Fatalf("contentUrl got %q, want %q", got, want)
	}
}
