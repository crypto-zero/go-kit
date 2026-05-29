// Package clientip extracts client IP addresses from Kratos request contexts.
package clientip

import (
	"context"
	"net"
	"strings"

	"github.com/go-kratos/kratos/v2/transport"
	kratoshttp "github.com/go-kratos/kratos/v2/transport/http"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// FromContext extracts the client IP address from a Kratos server context.
//
// Priority: X-Forwarded-For, X-Real-IP, then remote peer address. Returned
// values are normalized: IPv6 zone IDs are removed and IPv4-mapped IPv6
// addresses are converted to IPv4.
func FromContext(ctx context.Context) string {
	tr, ok := transport.FromServerContext(ctx)
	if !ok {
		return ""
	}
	if httpTr, ok := tr.(*kratoshttp.Transport); ok {
		return fromHTTP(httpTr)
	}
	return fromGRPC(ctx)
}

func fromHTTP(httpTr *kratoshttp.Transport) string {
	req := httpTr.Request()
	if req == nil {
		return ""
	}
	if ip := extract(req.Header.Get("X-Forwarded-For")); ip != "" {
		return ip
	}
	if ip := extract(req.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return normalize(req.RemoteAddr)
	}
	return normalize(host)
}

func fromGRPC(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if xff := md.Get("x-forwarded-for"); len(xff) > 0 {
			if ip := extract(xff[0]); ip != "" {
				return ip
			}
		}
		if xrip := md.Get("x-real-ip"); len(xrip) > 0 {
			if ip := extract(xrip[0]); ip != "" {
				return ip
			}
		}
	}
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		host, _, err := net.SplitHostPort(p.Addr.String())
		if err != nil {
			return normalize(p.Addr.String())
		}
		return normalize(host)
	}
	return ""
}

func extract(headerVal string) string {
	if headerVal == "" {
		return ""
	}
	if idx := strings.IndexByte(headerVal, ','); idx != -1 {
		headerVal = headerVal[:idx]
	}
	return normalize(strings.TrimSpace(headerVal))
}

func normalize(ip string) string {
	if ip == "" {
		return ""
	}
	if idx := strings.IndexByte(ip, '%'); idx != -1 {
		ip = ip[:idx]
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if ipv4 := parsed.To4(); ipv4 != nil {
		return ipv4.String()
	}
	return parsed.String()
}
