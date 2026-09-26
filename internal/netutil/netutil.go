// Package netutil resolves the physical sending interface and missing source addresses.
package netutil

import (
	"fmt"
	"net"
	"net/netip"
	"roce-cli/internal/config"
	"runtime"
)

func Resolve(c config.Config) (config.Config, net.Interface, error) {
	if runtime.GOOS != "linux" {
		return c, net.Interface{}, fmt.Errorf("send is supported only on Linux; use build for offline output")
	}
	iface, e := net.InterfaceByName(c.Interface)
	if e != nil {
		return c, net.Interface{}, e
	}
	l := c.Inner
	if c.Encap == "vxlan" {
		l = c.Outer
	}
	var addresses []net.Addr
	if !l.SrcIP.IsValid() {
		addresses, e = iface.Addrs()
		if e != nil {
			return c, *iface, e
		}
	}
	c, e = Complete(c, *iface, addresses)
	return c, *iface, e
}

// Complete is separated from discovery so ambiguous-address decisions are testable.
func Complete(c config.Config, iface net.Interface, addresses []net.Addr) (config.Config, error) {
	if iface.Flags&net.FlagUp == 0 {
		return c, fmt.Errorf("interface %s is down", iface.Name)
	}
	if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) != 6 {
		return c, fmt.Errorf("interface %s is not a 6-byte Ethernet interface", iface.Name)
	}
	if iface.MTU < 68 {
		return c, fmt.Errorf("interface MTU is too small")
	}
	if iface.MTU < c.MTU {
		c.MTU = iface.MTU
	}
	l := &c.Inner
	if c.Encap == "vxlan" {
		l = &c.Outer
	}
	if len(l.SrcMAC) == 0 {
		l.SrcMAC = append(net.HardwareAddr(nil), iface.HardwareAddr...)
	}
	if !l.SrcIP.IsValid() {
		candidates := map[netip.Addr]bool{}
		for _, addr := range addresses {
			p, e := netip.ParsePrefix(addr.String())
			if e != nil {
				continue
			}
			ip := p.Addr().Unmap()
			if ip.Is4() && ip.IsGlobalUnicast() {
				candidates[ip] = true
			}
		}
		if len(candidates) != 1 {
			return c, fmt.Errorf("interface %s has %d usable IPv4 addresses; specify source IPv4 explicitly", iface.Name, len(candidates))
		}
		for ip := range candidates {
			l.SrcIP = ip
		}
	}
	return c, nil
}
