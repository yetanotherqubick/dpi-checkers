package inetutil

import (
	"errors"
	"testing"
)

func TestTryHandleErrClassifiesKnownErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "handshake failure", err: errors.New("remote: handshake failure"), want: ErrTlsHandshakeFail},
		{name: "tls internal", err: errors.New("tls: internal error"), want: ErrTlsInternal},
		{name: "bad record mac", err: errors.New("tls: bad record MAC"), want: ErrTlsBadRecordMac},
		{name: "invalid key share", err: errors.New("tls: invalid server key share"), want: ErrTlsInvalidKeyShare},
		{name: "malformed http", err: errors.New("malformed HTTP response"), want: ErrHttpMalformedResponse},
		{name: "connection reset", err: errors.New("read: connection reset by peer"), want: ErrTcpConnReset},
		{name: "broken pipe", err: errors.New("write: broken pipe"), want: ErrTlsWriteBrokenPipe},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tryHandleErr(tt.err)
			if !ok {
				t.Fatal("error was not handled")
			}
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTryHandleErrPreservesUnknownErrors(t *testing.T) {
	want := errors.New("unrecognized network failure")
	got, ok := tryHandleErr(want)
	if ok {
		t.Fatal("unknown error was marked as handled")
	}
	if !errors.Is(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestIsInetutilErrRecognizesAllSentinels(t *testing.T) {
	tests := []error{
		ErrTcpConnReset,
		ErrTcpConnTimeout,
		ErrTcpWriteTimeout,
		ErrTcpReadTimeout,
		ErrTlsCertificateInvalid,
		ErrTlsHandshakeTimeout,
		ErrTlsHandshakeFail,
		ErrTlsInternal,
		ErrTlsBadRecordMac,
		ErrTlsInvalidKeyShare,
		ErrTlsWriteBrokenPipe,
		ErrHttpMalformedResponse,
		ErrInternal,
	}

	for _, err := range tests {
		if !IsInetutilErr(err) {
			t.Errorf("IsInetutilErr(%v) = false, want true", err)
		}
	}

	if IsInetutilErr(errors.New("not an inetutil error")) {
		t.Fatal("unknown error classified as inetutil error")
	}
}
