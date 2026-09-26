// Package cli parses flags without exiting or performing network/file I/O.
package cli

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"roce-cli/internal/config"
	"strconv"
	"strings"
	"time"
)

func Parse(args []string, out io.Writer) (config.Config, error) {
	c := config.Defaults()
	if len(args) == 2 && args[0] == "help" {
		return Parse([]string{args[1], "--help"}, out)
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(out, "Usage: roce-cli <command> [flags]\n\nCommands:\n  build    Generate RoCE frames as PCAP or hex (offline)\n  send     Submit raw Ethernet frames (Linux)\n  receive  Capture and validate incoming frames (Linux; alias: recv)\n  inspect  Decode and validate an Ethernet PCAP (offline)\n  version  Print version\n\nUse roce-cli <command> --help or roce-cli help <command>. No RDMA QP is created.")
		if len(args) == 0 {
			return c, fmt.Errorf("subcommand required")
		}
		return c, flag.ErrHelp
	}
	c.Command = args[0]
	if c.Command == "recv" {
		c.Command = "receive"
	}
	if c.Command == "receive" || c.Command == "inspect" {
		return parseObserve(c, args[1:], out)
	}
	if c.Command != "build" && c.Command != "send" {
		return c, fmt.Errorf("unknown subcommand %q", c.Command)
	}
	fs, values := newFlagSet(c.Command, out)
	if err := fs.Parse(args[1:]); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}
	s := func(k string) string { return values[k].text }
	has := func(k string) bool { return values[k].seen }
	b := func(k string) bool { return s(k) == "true" }
	var parseErr error
	n := func(k string, max uint64) uint64 {
		raw := s(k)
		if raw == "" && !has(k) {
			return 0
		}
		x, e := Uint(raw, max)
		if e != nil && parseErr == nil {
			parseErr = fmt.Errorf("--%s: %w", k, e)
		}
		return x
	}
	c.Template = s("template")
	c.Encap = s("encap")
	if c.Template != "send-only" && c.Template != "write-only" && c.Template != "cnp" {
		return c, fmt.Errorf("unknown template %q", c.Template)
	}
	if c.Encap != "none" && c.Encap != "vxlan" {
		return c, fmt.Errorf("unknown encap %q", c.Encap)
	}
	if !has("dqpn") {
		return c, fmt.Errorf("--dqpn is required")
	}
	c.DQPN = uint32(n("dqpn", 0xffffff))
	c.PSN = uint32(n("psn", 0xffffff))
	c.PSNStep = uint32(n("psn-step", 0xffffff))
	c.PKey = uint16(n("pkey", 0xffff))
	c.RemoteAddr = n("remote-addr", math.MaxUint64)
	c.RKey = uint32(n("rkey", math.MaxUint32))
	c.VNI = uint32(n("vni", 0xffffff))
	c.MTU = int(n("mtu", 65535))
	c.Count = n("count", math.MaxUint64)
	c.SrcPortStep = uint16(n("src-port-step", 65535))
	c.AckRequest = b("ack-request")
	c.BadICRC = b("bad-icrc")
	c.Continuous = b("continuous")
	c.Hex = b("hex")
	c.Overwrite = b("overwrite")
	c.PCAP = s("pcap")
	c.Interface = s("interface")
	if c.MTU < 68 {
		return c, fmt.Errorf("--mtu must be 68..65535")
	}
	if c.Count == 0 {
		return c, fmt.Errorf("--count must be positive")
	}
	for _, entry := range []struct {
		prefix string
		layer  *config.Layer
	}{{"", &c.Inner}, {"outer-", &c.Outer}} {
		p, l := entry.prefix, entry.layer
		l.SrcPort = uint16(n(p+"src-port", 65535))
		l.DstPort = uint16(n(p+"dst-port", 65535))
		l.DSCP = uint8(n(p+"dscp", 63))
		l.ECN = uint8(n(p+"ecn", 3))
		l.TTL = uint8(n(p+"ttl", 255))
		l.PCP = uint8(n(p+"pcp", 7))
		if l.TTL == 0 {
			return c, fmt.Errorf("--%sttl must be positive", p)
		}
		if has(p + "vlan-id") {
			l.VLAN = int(n(p+"vlan-id", 4094))
		} else if has(p + "pcp") {
			return c, fmt.Errorf("--%spcp requires --%svlan-id", p, p)
		}
		if s(p+"udp-checksum") != "auto" && s(p+"udp-checksum") != "zero" {
			return c, fmt.Errorf("--%sudp-checksum must be auto or zero", p)
		}
		l.ZeroChecksum = s(p+"udp-checksum") == "zero"
		active := p == "" || c.Encap == "vxlan"
		autoSource := c.Command == "send" && ((p == "" && c.Encap == "none") || (p == "outer-" && c.Encap == "vxlan"))
		for _, a := range []struct {
			name string
			dst  *net.HardwareAddr
		}{{"src-mac", &l.SrcMAC}, {"dst-mac", &l.DstMAC}} {
			key := p + a.name
			if !has(key) && (!active || (a.name == "src-mac" && autoSource)) {
				continue
			}
			mac, e := net.ParseMAC(s(key))
			if e != nil || len(mac) != 6 {
				return c, fmt.Errorf("--%s requires a 6-byte MAC", key)
			}
			*a.dst = mac
		}
		for _, a := range []struct {
			name string
			dst  *netip.Addr
		}{{"src-ip", &l.SrcIP}, {"dst-ip", &l.DstIP}} {
			key := p + a.name
			if !has(key) && (!active || (a.name == "src-ip" && autoSource)) {
				continue
			}
			ip, e := netip.ParseAddr(s(key))
			if e != nil || !ip.Is4() {
				return c, fmt.Errorf("--%s requires IPv4", key)
			}
			*a.dst = ip
		}
	}
	if parseErr != nil {
		return c, parseErr
	}
	forbidden := func(keys ...string) error {
		for _, k := range keys {
			if has(k) {
				return fmt.Errorf("--%s is not valid for this template/mode", k)
			}
		}
		return nil
	}
	if c.Encap == "none" {
		for k, v := range values {
			if v.seen && (strings.HasPrefix(k, "outer-") || k == "vni") {
				return c, fmt.Errorf("--%s requires --encap vxlan", k)
			}
		}
	} else if !has("vni") || c.VNI == 0 {
		return c, fmt.Errorf("vxlan requires --vni 1..0xffffff")
	}
	if c.Template == "write-only" {
		if !has("remote-addr") || !has("rkey") {
			return c, fmt.Errorf("write-only requires --remote-addr and --rkey (zero allowed)")
		}
	} else if e := forbidden("remote-addr", "rkey"); e != nil {
		return c, e
	}
	if c.Template == "cnp" {
		if e := forbidden("payload-hex", "psn", "psn-step", "psn-list", "ack-request"); e != nil {
			return c, e
		}
		if !has("src-port") {
			c.Inner.SrcPort = 0
		}
	}
	var err error
	c.Payload, err = hex.DecodeString(s("payload-hex"))
	if err != nil {
		return c, fmt.Errorf("--payload-hex: %w", err)
	}
	c.Interval, err = time.ParseDuration(s("interval"))
	if err != nil || c.Interval < 0 {
		return c, fmt.Errorf("--interval requires a nonnegative Go duration")
	}
	c.Duration, err = time.ParseDuration(s("duration"))
	if err != nil || (has("duration") && c.Duration <= 0) {
		return c, fmt.Errorf("--duration requires a positive Go duration")
	}
	if has("psn-list") {
		if e := forbidden("psn", "psn-step", "count", "duration", "continuous"); e != nil {
			return c, e
		}
		for _, item := range strings.Split(s("psn-list"), ",") {
			x, e := Uint(item, 0xffffff)
			if e != nil {
				return c, fmt.Errorf("--psn-list: %w", e)
			}
			c.PSNList = append(c.PSNList, uint32(x))
		}
	}
	modes := 0
	for _, k := range []string{"count", "duration", "continuous"} {
		if has(k) {
			modes++
		}
	}
	if modes > 1 {
		return c, fmt.Errorf("--count, --duration and --continuous are mutually exclusive")
	}
	if has("continuous") && !c.Continuous {
		return c, fmt.Errorf("--continuous must be true when specified")
	}
	if c.Command == "build" {
		if e := forbidden("interface", "duration", "continuous"); e != nil {
			return c, e
		}
		if (has("pcap") && has("hex")) || (c.PCAP != "") == c.Hex {
			return c, fmt.Errorf("build requires exactly one of --pcap FILE or --hex")
		}
		if has("overwrite") && (c.PCAP == "" || c.PCAP == "-") {
			return c, fmt.Errorf("--overwrite requires a PCAP file path")
		}
		if err := ValidateTimestamps(c.FrameCount(), c.Interval); err != nil {
			return c, err
		}
	} else {
		if e := forbidden("pcap", "hex", "overwrite"); e != nil {
			return c, e
		}
		if c.Interface == "" {
			return c, fmt.Errorf("send requires --interface")
		}
	}
	return c, nil
}

func Uint(s string, max uint64) (uint64, error) {
	base := 10
	digits := s
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		digits = s[2:]
	}
	if digits == "" || strings.HasPrefix(digits, "+") || strings.HasPrefix(digits, "-") {
		return 0, fmt.Errorf("invalid unsigned integer %q", s)
	}
	n, e := strconv.ParseUint(digits, base, 64)
	if e != nil || n > max {
		return 0, fmt.Errorf("integer %q must be 0..%d", s, max)
	}
	return n, nil
}

// Classic PCAP uses uint32 seconds; check before creating any output file.
func ValidateTimestamps(count uint64, interval time.Duration) error {
	const limit = uint64(math.MaxUint32)*1_000_000 + 999999
	if count == 0 || interval < 0 {
		return errors.New("count must be positive and interval nonnegative")
	}
	if interval%time.Microsecond != 0 {
		return errors.New("build --interval must be an exact number of microseconds")
	}
	step := uint64(interval / time.Microsecond)
	if step > 0 && count-1 > limit/step {
		return errors.New("PCAP timestamp exceeds uint32 seconds")
	}
	return nil
}
