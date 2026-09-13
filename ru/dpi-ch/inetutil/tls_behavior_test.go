package inetutil

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/config"
	tls "github.com/refraction-networking/utls"
)

func preserveTLSTestConfig(t *testing.T) {
	t.Helper()
	old := config.Get().InetUtil
	t.Cleanup(func() {
		config.Get().InetUtil = old
	})
	config.Get().InetUtil.Fingerprint = "chrome"
	config.Get().InetUtil.KeyLogPath = ""
}

func TestGetHandshakedUTlsConnRejectsUntrustedCertificate(t *testing.T) {
	preserveTLSTestConfig(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	ip, port := tlsTestServerEndpoint(t, server.Listener.Addr())

	conn, err := GetHandshakedUTlsConn(TlsConnOpt{
		Ctx:            context.Background(),
		Ip:             ip,
		Port:           port,
		Sni:            "example.test",
		InsecureVerify: true,
	})
	if conn != nil {
		conn.Close()
	}
	if err != ErrTlsCertificateInvalid {
		t.Fatalf("got %v, want %v", err, ErrTlsCertificateInvalid)
	}
}

func TestTlsHttpHelpersRoundTrip(t *testing.T) {
	preserveTLSTestConfig(t)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("got method %s, want GET", r.Method)
		}
		if r.URL.Path != "/test" {
			t.Errorf("got path %q, want %q", r.URL.Path, "/test")
		}
		w.Header().Set("X-Test", "ok")
		w.WriteHeader(http.StatusNoContent)
	}))
	server.StartTLS()
	defer server.Close()
	ip, port := tlsTestServerEndpoint(t, server.Listener.Addr())

	conn, err := GetHandshakedUTlsConn(TlsConnOpt{
		Ctx:            context.Background(),
		Ip:             ip,
		Port:           port,
		Sni:            "example.test",
		InsecureVerify: false,
	})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	req, err := http.NewRequest(http.MethodGet, "https://example.test/test", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	n, err := TlsWriteHttpRequest(context.Background(), conn, req)
	if err != nil {
		t.Fatalf("TlsWriteHttpRequest: %v", err)
	}
	if n <= 0 {
		t.Fatalf("wrote %d bytes, want positive byte count", n)
	}

	resp, err := TlsReadHttpResponse(context.Background(), conn, bufio.NewReader(conn))
	if err != nil {
		t.Fatalf("TlsReadHttpResponse: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("got status %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if got := resp.Header.Get("X-Test"); got != "ok" {
		t.Fatalf("got X-Test %q, want %q", got, "ok")
	}
}

func TestSetUTlsAlpnReplacesExistingAlpn(t *testing.T) {
	spec := tlsClientHelloSpecWithAlpn([]string{"h2", "http/1.1"})
	setUTlsAlpn(spec, []string{"http/1.1"})

	found := false
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*tls.ALPNExtension); ok {
			found = true
			if len(alpn.AlpnProtocols) != 1 || alpn.AlpnProtocols[0] != "http/1.1" {
				t.Fatalf("got ALPN %v, want [http/1.1]", alpn.AlpnProtocols)
			}
		}
	}
	if !found {
		t.Fatal("ALPN extension not found")
	}
}

func tlsTestServerEndpoint(t *testing.T, addr net.Addr) (netip.Addr, int) {
	t.Helper()

	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address type %T, want *net.TCPAddr", addr)
	}
	return netip.MustParseAddr(tcpAddr.IP.String()), tcpAddr.Port
}

func tlsClientHelloSpecWithAlpn(protos []string) *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{Extensions: []tls.TLSExtension{
		&tls.ALPNExtension{AlpnProtocols: protos},
	}}
}
