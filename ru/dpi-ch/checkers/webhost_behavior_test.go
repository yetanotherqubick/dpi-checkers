package checkers

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/config"
	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/inetutil"
)

func preserveWebhostTestConfig(t *testing.T) {
	t.Helper()
	oldInetUtil := config.Get().InetUtil
	oldWebhost := config.Get().Checkers.Webhost
	t.Cleanup(func() {
		config.Get().InetUtil = oldInetUtil
		config.Get().Checkers.Webhost = oldWebhost
	})
	config.Get().InetUtil.Fingerprint = "chrome"
	config.Get().Checkers.Webhost.TcpWriteTimeout = time.Second
	config.Get().Checkers.Webhost.TcpReadTimeout = time.Second
	config.Get().Checkers.Webhost.Tcp1620nBytes = 128
}

func TestWebhostHandshakesCheckAcceptsSuccessfulHandshake(t *testing.T) {
	preserveWebhostTestConfig(t)

	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	defer srv.Close()

	ip, port := testServerEndpoint(t, srv.Listener.Addr())
	conn, err := webhostHandshakesCheck(
		WebhostSingleOpt{Sni: "example.test"},
		inetutil.TlsConnOpt{
			Ip:             ip,
			Port:           port,
			Sni:            "example.test",
			InsecureVerify: false,
		},
	)
	if err != nil {
		t.Fatalf("got %v, want successful handshake", err)
	}
	if conn == nil {
		t.Fatal("got nil connection after successful handshake")
	}
	conn.Close()
}

func TestWebhostHandshakesCheckDetectsSniBlocking(t *testing.T) {
	preserveWebhostTestConfig(t)

	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	srv.TLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName == "blocked.test" {
			return nil, net.ErrClosed
		}
		return nil, nil
	}
	defer srv.Close()

	ip, port := testServerEndpoint(t, srv.Listener.Addr())
	conn, err := webhostHandshakesCheck(
		WebhostSingleOpt{Sni: "blocked.test"},
		inetutil.TlsConnOpt{
			Ip:             ip,
			Port:           port,
			Sni:            "blocked.test",
			InsecureVerify: false,
		},
	)
	if conn != nil {
		conn.Close()
	}
	if err != ErrWebhostBlockedBySni {
		t.Fatalf("got %v, want %v", err, ErrWebhostBlockedBySni)
	}
}

func TestWebhostAliveCheckSendsHeadAndAcceptsResponse(t *testing.T) {
	preserveWebhostTestConfig(t)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("got method %s, want HEAD", r.Method)
		}
		if got := r.Host; got != "example.test" {
			t.Errorf("got Host %q, want %q", got, "example.test")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.StartTLS()
	defer server.Close()

	ip, port := testServerEndpoint(t, server.Listener.Addr())
	conn, err := webhostHandshakesCheck(
		WebhostSingleOpt{Sni: "example.test"},
		inetutil.TlsConnOpt{
			Ip:             ip,
			Port:           port,
			Sni:            "example.test",
			InsecureVerify: false,
		},
	)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	if err := webhostAliveCheck(WebhostSingleOpt{
		Ctx:  context.Background(),
		Host: "example.test",
	}, conn); err != nil {
		t.Fatalf("webhostAliveCheck: %v", err)
	}
}

func TestWebhostTcp1620CheckPostsConfiguredBody(t *testing.T) {
	preserveWebhostTestConfig(t)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("got method %s, want POST", r.Method)
		}
		if got := r.Host; got != "example.test" {
			t.Errorf("got Host %q, want %q", got, "example.test")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		if len(body) != config.Get().Checkers.Webhost.Tcp1620nBytes {
			t.Errorf("got body length %d, want %d", len(body), config.Get().Checkers.Webhost.Tcp1620nBytes)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	server.StartTLS()
	defer server.Close()

	ip, port := testServerEndpoint(t, server.Listener.Addr())
	thp, err := webhostTcp1620check(
		WebhostSingleOpt{Ctx: context.Background(), Host: "example.test"},
		inetutil.TlsConnOpt{
			Ctx:            context.Background(),
			Ip:             ip,
			Port:           port,
			Sni:            "example.test",
			InsecureVerify: false,
		},
	)
	if err != nil {
		t.Fatalf("webhostTcp1620check: %v", err)
	}
	if thp.TxBytes <= int64(config.Get().Checkers.Webhost.Tcp1620nBytes) {
		t.Fatalf("TxBytes=%d, want more than request body size", thp.TxBytes)
	}
	if thp.RxBytes == 0 {
		t.Fatal("RxBytes is zero")
	}
}

func TestRandomHostnameFormat(t *testing.T) {
	const alphabet = RANDOM_HOSTNAME_ALPHABET

	for range 100 {
		host, err := randomHostname()
		if err != nil {
			t.Fatalf("randomHostname: %v", err)
		}

		parts := strings.Split(host, ".")
		if len(parts) != 2 || len(parts[0]) != RANDOM_HOSTNAME_LEN || parts[1] != "com" {
			t.Fatalf("got hostname %q with unexpected format", host)
		}
		for _, r := range parts[0] {
			if !strings.ContainsRune(alphabet, r) {
				t.Fatalf("hostname %q contains invalid character %q", host, r)
			}
		}
	}
}

func testServerEndpoint(t *testing.T, addr net.Addr) (netip.Addr, int) {
	t.Helper()

	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address type %T, want *net.TCPAddr", addr)
	}
	return netip.MustParseAddr(tcpAddr.IP.String()), tcpAddr.Port
}
