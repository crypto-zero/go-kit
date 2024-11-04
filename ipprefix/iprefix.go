package ipprefix

import (
	"net"
	"net/netip"
)

// IPv4PrivatePrefixes is a list of IPv4 private prefixes define in RFC 1918.
var IPv4PrivatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// IPv6PrivatePrefixes is a list of IPv6 private prefixes define in RFC 4193.
var IPv6PrivatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("fd00::/8"),
}

// IPv6LoopbackPrefix is the IPv6 loopback prefix defined in RFC 4291.
var IPv6LoopbackPrefix = netip.MustParsePrefix("fe80::/10")

// IsPrivate returns true if the given IP address is a private address.
func IsPrivate(ip net.IP) bool {
	if ip.To4() != nil {
		var ipd [4]byte
		copy(ipd[:], ip.To4())
		return IsIPv4Private(netip.AddrFrom4(ipd))
	}
	var ipd [16]byte
	copy(ipd[:], ip.To16())
	return IsIPv6Private(netip.AddrFrom16(ipd))
}

// IsIPv4Private returns true if the given IPv4 address is a private address.
func IsIPv4Private(ip netip.Addr) bool {
	for _, prefix := range IPv4PrivatePrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// IsIPv6Private returns true if the given IPv6 address is a private address.
func IsIPv6Private(ip netip.Addr) bool {
	for _, prefix := range IPv6PrivatePrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return IPv6LoopbackPrefix.Contains(ip)
}
