package clientip

import (
	"context"
	"net"
	"testing"

	"github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

type mockTransport struct{}

func (m *mockTransport) Kind() transport.Kind { return transport.KindGRPC }
func (m *mockTransport) Endpoint() string     { return "localhost:9000" }
func (m *mockTransport) Operation() string    { return "/test.Service/Method" }
func (m *mockTransport) RequestHeader() transport.Header {
	return &mockHeader{}
}
func (m *mockTransport) ReplyHeader() transport.Header {
	return &mockHeader{}
}

type mockHeader struct{}

func (m *mockHeader) Get(string) string      { return "" }
func (m *mockHeader) Set(string, string)     {}
func (m *mockHeader) Add(string, string)     {}
func (m *mockHeader) Keys() []string         { return nil }
func (m *mockHeader) Values(string) []string { return nil }

func TestFromContextUsesForwardedHeader(t *testing.T) {
	ctx := transport.NewServerContext(context.Background(), &mockTransport{})
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(
		"x-forwarded-for", " ::ffff:192.168.1.10, 10.0.0.1",
		"x-real-ip", "192.168.1.11",
	))

	if got := FromContext(ctx); got != "192.168.1.10" {
		t.Fatalf("FromContext() = %q, want forwarded IP", got)
	}
}

func TestFromContextFallsBackToPeer(t *testing.T) {
	ctx := transport.NewServerContext(context.Background(), &mockTransport{})
	ctx = peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}})

	if got := FromContext(ctx); got != "2001:db8::1" {
		t.Fatalf("FromContext() = %q, want peer IP", got)
	}
}

func TestFromContextRequiresServerTransport(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-real-ip", "192.168.1.1"))

	if got := FromContext(ctx); got != "" {
		t.Fatalf("FromContext() = %q, want empty without server transport", got)
	}
}

func TestNormalizeRejectsInvalidIP(t *testing.T) {
	if got := normalize("not-an-ip"); got != "" {
		t.Fatalf("normalize() = %q, want empty", got)
	}
}
