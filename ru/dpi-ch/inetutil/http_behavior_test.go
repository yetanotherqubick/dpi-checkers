package inetutil

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/config"
)

func preserveHTTPTestConfig(t *testing.T) {
	t.Helper()
	old := config.Get().InetUtil
	t.Cleanup(func() {
		config.Get().InetUtil = old
	})
}

func TestHeadUsesRequestedMethodAndHeaders(t *testing.T) {
	preserveHTTPTestConfig(t)
	config.Get().InetUtil.BrowserHeaders = map[string]string{"X-Test-Header": "value"}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("got method %s, want HEAD", r.Method)
		}
		if got := r.Header.Get("X-Test-Header"); got != "value" {
			t.Errorf("got X-Test-Header %q, want %q", got, "value")
		}
		if !r.Close {
			t.Error("request Close is false, want true")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if err := Head(context.Background(), server.URL, true, true); err != nil {
		t.Fatalf("Head: %v", err)
	}
}

func TestGetReturnsResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("response body"))
	}))
	defer server.Close()

	got, err := Get(context.Background(), server.URL, false, true)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "response body" {
		t.Fatalf("got %q, want %q", got, "response body")
	}
}

func TestGetAndUnmarshal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]int{"value": 42})
	}))
	defer server.Close()

	var got map[string]int
	if err := GetAndUnmarshal(context.Background(), server.URL, &got, false, true); err != nil {
		t.Fatalf("GetAndUnmarshal: %v", err)
	}
	if got["value"] != 42 {
		t.Fatalf("got %v, want value=42", got)
	}
}

func TestGetAndUnmarshalRejectsInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer server.Close()

	var got map[string]int
	if err := GetAndUnmarshal(context.Background(), server.URL, &got, false, true); err == nil {
		t.Fatal("expected invalid JSON to fail")
	}
}

func TestHeadHonorsContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := Head(ctx, server.URL, false, true); err == nil {
		t.Fatal("expected cancelled request to fail")
	}
}

func TestSetHeadersReplacesExistingValues(t *testing.T) {
	h := make(http.Header)
	h.Set("X-Test", "old")
	SetHeaders(&h, map[string]string{"X-Test": "new", "X-Other": "value"})

	if got := h.Get("X-Test"); got != "new" {
		t.Fatalf("got X-Test %q, want %q", got, "new")
	}
	if got := h.Get("X-Other"); got != "value" {
		t.Fatalf("got X-Other %q, want %q", got, "value")
	}
}
