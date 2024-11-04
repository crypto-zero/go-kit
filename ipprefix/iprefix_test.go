package ipprefix

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsPrivate(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{
			name: "IPv4 Private",
			ip:   "192.168.1.1",
			want: true,
		},
		{
			name: "IPv4 Public",
			ip:   "8.8.8.8",
			want: false,
		},
		{
			name: "IPv6 Private",
			ip:   "fe80::1",
			want: true,
		},
		{
			name: "IPv6 Public",
			ip:   "2001:4860:4860::8888",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPrivate(net.ParseIP(tt.ip))
			assert.Equal(t, tt.want, got)
		})
	}
}
