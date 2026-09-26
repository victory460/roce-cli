package netutil

import (
	"net"
	"net/netip"
	"roce-cli/internal/config"
	"testing"
)

func TestComplete(t *testing.T) {
	iface := net.Interface{Name: "test", MTU: 1400, Flags: net.FlagUp, HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}}
	addr := func(s string) net.Addr { _, n, _ := net.ParseCIDR(s); return n }
	c := config.Defaults()
	r, e := Complete(c, iface, []net.Addr{addr("192.0.2.1/32"), addr("fe80::1/64")})
	if e != nil || r.MTU != 1400 || r.Inner.SrcIP.String() != "192.0.2.1" || r.Inner.SrcMAC.String() != iface.HardwareAddr.String() {
		t.Fatal(r, e)
	}
	for _, addresses := range [][]net.Addr{nil, {addr("169.254.1.1/32")}, {addr("192.0.2.1/32"), addr("192.0.2.2/32")}} {
		if _, e := Complete(c, iface, addresses); e == nil {
			t.Fatal(addresses)
		}
	}
	c.Inner.SrcIP = netip.MustParseAddr("203.0.113.1")
	c.Inner.SrcMAC = net.HardwareAddr{2, 0, 0, 0, 0, 7}
	r, e = Complete(c, iface, nil)
	if e != nil || r.Inner.SrcIP != c.Inner.SrcIP || r.Inner.SrcMAC.String() != c.Inner.SrcMAC.String() {
		t.Fatal(r, e)
	}
	c.Encap = "vxlan"
	r, e = Complete(c, iface, []net.Addr{addr("192.0.2.1/32")})
	if e != nil || r.Inner.SrcIP != c.Inner.SrcIP || r.Outer.SrcIP.String() != "192.0.2.1" {
		t.Fatal(r, e)
	}
	iface.Flags = 0
	if _, e := Complete(c, iface, nil); e == nil {
		t.Fatal("down interface")
	}
	iface.Flags = net.FlagUp | net.FlagLoopback
	if _, e := Complete(c, iface, nil); e == nil {
		t.Fatal("loopback")
	}
}
