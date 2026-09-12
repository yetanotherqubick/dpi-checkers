package inetutil

import (
	"slices"
	"testing"
)

func TestTlsSanCnPrefersBaseDomain(t *testing.T) {
	got := TlsSanCn(
		[]string{"www.example.com", "*.example.com", "example.com"},
		"ignored.example.net",
	)
	want := TlsSanCnItem{Name: "example.com", Wild: true, Single: true, Some: true}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestTlsSanCnUsesWildcardAsPrimaryWhenBaseIsAbsent(t *testing.T) {
	got := TlsSanCn([]string{"*.example.com"}, "")
	want := TlsSanCnItem{Name: "example.com", Wild: true}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestTlsSanCnReportsSingleSubdomainWithoutWildcard(t *testing.T) {
	got := TlsSanCn([]string{"www.example.com"}, "")
	want := TlsSanCnItem{Name: "www.example.com", Single: true}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestTlsSanCnIgnoresNamesWithoutEffectiveTLDPlusOne(t *testing.T) {
	got := TlsSanCn([]string{"localhost", "invalid"}, "")
	if got != (TlsSanCnItem{}) {
		t.Fatalf("got %+v, want empty result", got)
	}
}

func TestTlsSanCnMergeIncludesWildcardAndDeepSubdomain(t *testing.T) {
	got := tlsSanCnMerge([]string{"*.example.com", "www.example.com", "api.sub.example.com"}, "cn.example.com")
	keys := make([]string, 0, len(got))
	for name := range got {
		keys = append(keys, name)
	}
	slices.Sort(keys)

	want := []string{"*.example.com", "api.sub.example.com"}
	if !slices.Equal(keys, want) {
		t.Fatalf("got names %v, want %v", keys, want)
	}
}
