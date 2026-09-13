package checkers

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/config"
	"golang.org/x/net/dns/dnsmessage"
)

type testDNSResponseMode int

const (
	testDNSA testDNSResponseMode = iota
	testDNSNXDomain
	testDNSAAAAOnly
)

func preserveDnsResolveConfig(t *testing.T) {
	t.Helper()
	old := config.Get().Checkers.Dns.Resolve.PlainOpt
	t.Cleanup(func() {
		config.Get().Checkers.Dns.Resolve.PlainOpt = old
	})
	config.Get().Checkers.Dns.Resolve.PlainOpt.Timeout = time.Second
}

func TestDnsPlainAReturnsIPv4Answers(t *testing.T) {
	preserveDnsResolveConfig(t)
	addr := startTestDNSServer(t, testDNSA)

	got, err := dnsPlainA(context.Background(), addr, "example.test")
	if err != nil {
		t.Fatalf("dnsPlainA: %v", err)
	}

	want := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDnsPlainAReturnsNXDOMAIN(t *testing.T) {
	preserveDnsResolveConfig(t)
	addr := startTestDNSServer(t, testDNSNXDomain)

	_, err := dnsPlainA(context.Background(), addr, "missing.test")
	if err == nil {
		t.Fatal("expected NXDOMAIN error")
	}

	dnsErr, ok := err.(*net.DNSError)
	if !ok {
		t.Fatalf("got error type %T, want *net.DNSError", err)
	}
	if !dnsErr.IsNotFound {
		t.Fatalf("got %+v, want IsNotFound=true", dnsErr)
	}
}

func TestDnsPlainADropsIPv6Answers(t *testing.T) {
	preserveDnsResolveConfig(t)
	addr := startTestDNSServer(t, testDNSAAAAOnly)

	got, err := dnsPlainA(context.Background(), addr, "ipv6-only.test")
	if err != nil {
		t.Fatalf("dnsPlainA: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want no IPv4 answers", got)
	}
}

func startTestDNSServer(t *testing.T, mode testDNSResponseMode) string {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 4096)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}

			response, err := makeTestDNSResponse(buf[:n], mode)
			if err == nil {
				_, _ = conn.WriteToUDP(response, peer)
			}
		}
	}()

	return conn.LocalAddr().String()
}

func makeTestDNSResponse(query []byte, mode testDNSResponseMode) ([]byte, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil, err
	}
	question, err := parser.Question()
	if err != nil {
		return nil, err
	}

	responseHeader := dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		RecursionDesired:   header.RecursionDesired,
		RecursionAvailable: true,
	}
	if mode == testDNSNXDomain {
		responseHeader.RCode = dnsmessage.RCodeNameError
	}

	builder := dnsmessage.NewBuilder(nil, responseHeader)
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}

	switch mode {
	case testDNSA:
		if question.Type == dnsmessage.TypeA {
			if err := builder.AResource(dnsmessage.ResourceHeader{
				Name:  question.Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}); err != nil {
				return nil, err
			}
		}
	case testDNSAAAAOnly:
		if question.Type == dnsmessage.TypeAAAA {
			if err := builder.AAAAResource(dnsmessage.ResourceHeader{
				Name:  question.Name,
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
			}, dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::1").As16()}); err != nil {
				return nil, err
			}
		}
	}

	return builder.Finish()
}
