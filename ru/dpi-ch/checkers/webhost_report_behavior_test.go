package checkers

import (
	"errors"
	"testing"

	"github.com/hyperion-cs/dpi-checkers/ru/dpi-ch/inetutil"
)

func TestWebhostPrettyAlive(t *testing.T) {
	tests := []struct {
		err  error
		want FullCheckStatusDto
	}{
		{nil, FullCheckStatusDto{Msg: "Ok", Code: "OK"}},
		{inetutil.ErrHttpMalformedResponse, FullCheckStatusDto{Msg: "Ok, custom HTTP", Code: "OK_CUSTOM_HTTP"}},
		{errors.New("failed"), FullCheckStatusDto{Msg: "failed", Code: "ERR"}},
	}
	for _, tt := range tests {
		if got := webhostPrettyAlive(tt.err); got != tt.want {
			t.Errorf("webhostPrettyAlive(%v) = %+v, want %+v", tt.err, got, tt.want)
		}
	}
}

func TestWebhostPrettyTlsV(t *testing.T) {
	tests := []struct {
		v    uint16
		want string
	}{
		{0x0301, "1.0"},
		{0x0302, "1.1"},
		{0x0303, "1.2"},
		{0x0304, "1.3"},
		{0, " — "},
	}
	for _, tt := range tests {
		if got := webhostPrettyTlsV(tt.v); got != tt.want {
			t.Errorf("webhostPrettyTlsV(%#x) = %q, want %q", tt.v, got, tt.want)
		}
	}
}

func TestWebhostPrettyTcp1620(t *testing.T) {
	tests := []struct {
		err  error
		want FullCheckStatusDto
	}{
		{nil, FullCheckStatusDto{Msg: "No", Code: "OK"}},
		{inetutil.ErrTcpWriteTimeout, FullCheckStatusDto{Msg: "Detected", Code: "DETECTED"}},
		{inetutil.ErrTcpReadTimeout, FullCheckStatusDto{Msg: "Detected", Code: "DETECTED"}},
		{ErrWebhostSkip, FullCheckStatusDto{Msg: "Skipped", Code: "SKIP"}},
		{inetutil.ErrTlsWriteBrokenPipe, FullCheckStatusDto{Msg: "Not supported by host", Code: "NOT_SUPPORTED_BY_HOST"}},
		{errors.New("failed"), FullCheckStatusDto{Msg: "failed", Code: "ERR"}},
	}
	for _, tt := range tests {
		if got := webhostPrettyTcp1620(tt.err); got != tt.want {
			t.Errorf("webhostPrettyTcp1620(%v) = %+v, want %+v", tt.err, got, tt.want)
		}
	}
}

func TestWebhostPrettySiberian(t *testing.T) {
	tests := []struct {
		err  error
		want FullCheckStatusDto
	}{
		{nil, FullCheckStatusDto{Msg: "No", Code: "OK"}},
		{inetutil.ErrTlsHandshakeTimeout, FullCheckStatusDto{Msg: "Detected", Code: "DETECTED"}},
		{inetutil.ErrTlsHandshakeFail, FullCheckStatusDto{Msg: "Detected", Code: "DETECTED"}},
		{ErrWebhostSkip, FullCheckStatusDto{Msg: "Skipped", Code: "SKIP"}},
		{errors.New("failed"), FullCheckStatusDto{Msg: "failed", Code: "ERR"}},
	}
	for _, tt := range tests {
		if got := webhostPrettySiberian(tt.err); got != tt.want {
			t.Errorf("webhostPrettySiberian(%v) = %+v, want %+v", tt.err, got, tt.want)
		}
	}
}
