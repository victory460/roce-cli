package cli

import (
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func args(extra ...string) []string {
	a := strings.Fields("build --src-mac 02:00:00:00:00:01 --dst-mac 02:00:00:00:00:02 --src-ip 192.0.2.1 --dst-ip 192.0.2.2 --dqpn 0x123 --hex")
	return append(a, extra...)
}
func TestInvalidFlags(t *testing.T) {
	cases := []string{
		"--template invalid", "--encap invalid", "--dqpn 1", "--dscp 64", "--dscp 256", "--ecn 4", "--ttl 0", "--ttl 256", "--vlan-id 4095", "--pcp 0", "--vlan-id 0 --pcp 8", "--src-port 65536", "--dst-port -1", "--udp-checksum invalid",
		"--psn 0x1000000", "--psn-step 16777216", "--pkey 65536", "--count 0", "--count -1", "--count 18446744073709551616", "--mtu 67", "--mtu 65536", "--payload-hex a", "--payload-hex zz",
		"--template write-only", "--template write-only --remote-addr 0", "--template write-only --remote-addr 18446744073709551616 --rkey 0", "--template write-only --remote-addr 0 --rkey 4294967296", "--remote-addr 0", "--rkey 0",
		"--template cnp --psn 0", "--template cnp --psn-step 0", "--template cnp --ack-request=false", "--template cnp --payload-hex=", "--template cnp --psn-list 0", "--psn-list 1,2 --count 2", "--psn-list 1,2 --psn 0", "--psn-list 1,2 --psn-step 0", "--psn-list 1,", "--psn-list -1", "--psn-list 0x1000000",
		"--outer-dscp 0", "--vni 0", "--encap vxlan", "--duration 1s", "--continuous", "--continuous=false", "--interface eth0", "--overwrite=false", "--interval -1s", "--interval 1ns", "--interval 2562047h --count 999999999999", "--unknown", "trailing",
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			if c, e := Parse(args(strings.Fields(tc)...), io.Discard); e == nil {
				t.Fatalf("accepted %+v", c)
			}
		})
	}
}
func TestValidFlags(t *testing.T) {
	c, e := Parse(args("--template", "write-only", "--remote-addr", "0", "--rkey", "0", "--vlan-id", "0", "--pcp", "7", "--psn-list", "100,101,101,103,102", "--src-port-step", "65535"), io.Discard)
	if e != nil {
		t.Fatal(e)
	}
	if c.Inner.VLAN != 0 || c.RemoteAddr != 0 || c.RKey != 0 || !reflect.DeepEqual(c.PSNList, []uint32{100, 101, 101, 103, 102}) || c.FrameCount() != 5 {
		t.Fatalf("%+v", c)
	}
	c, e = Parse(args("--template", "cnp"), io.Discard)
	if e != nil || c.Inner.SrcPort != 0 {
		t.Fatal(c, e)
	}
	c, e = Parse(args("--template", "cnp", "--src-port", "8"), io.Discard)
	if e != nil || c.Inner.SrcPort != 8 {
		t.Fatal(c, e)
	}
	c, e = Parse(args("--psn", "00019", "--src-port", "0xFFFF"), io.Discard)
	if e != nil || c.PSN != 19 || c.Inner.SrcPort != 65535 {
		t.Fatal(c, e)
	}
}
func TestAddressesAndModes(t *testing.T) {
	a := args()
	for i := range a {
		if a[i] == "192.0.2.1" {
			a[i] = "::ffff:192.0.2.1"
		}
	}
	if _, e := Parse(a, io.Discard); e == nil {
		t.Fatal("mapped IPv6 accepted")
	}
	a = strings.Fields("send --interface eth0 --dst-mac 02:00:00:00:00:02 --dst-ip 192.0.2.2 --dqpn 0")
	c, e := Parse(a, io.Discard)
	if e != nil || c.Inner.SrcIP.IsValid() || len(c.Inner.SrcMAC) > 0 {
		t.Fatal(c, e)
	}
	for _, tc := range []string{"--hex=false", "--pcap=x", "--overwrite=false", "--count 1 --duration 1s", "--continuous --count 1", "--duration 0", "--duration -1s", "--psn-list 1 --continuous"} {
		if _, e := Parse(append(append([]string{}, a...), strings.Fields(tc)...), io.Discard); e == nil {
			t.Fatal(tc)
		}
	}
	for _, tc := range []string{"--count 1", "--duration 1s", "--continuous", "--psn-list 1,0,1"} {
		if _, e := Parse(append(append([]string{}, a...), strings.Fields(tc)...), io.Discard); e != nil {
			t.Fatal(tc, e)
		}
	}
}
func TestTimestampLimits(t *testing.T) {
	for _, tc := range []struct {
		count    uint64
		interval time.Duration
		ok       bool
	}{{1, time.Microsecond, true}, {4294967296, time.Second, true}, {4294967297, time.Second, false}, {^uint64(0), 0, true}, {^uint64(0), time.Microsecond, false}, {1, time.Nanosecond, false}} {
		if e := ValidateTimestamps(tc.count, tc.interval); (e == nil) != tc.ok {
			t.Fatal(tc, e)
		}
	}
}
func TestUnsignedParsing(t *testing.T) {
	for _, s := range []string{"", "-1", "+1", " 1", "1 ", "0x", "0x+1", "0b10", "1_000", "18446744073709551616"} {
		if _, e := Uint(s, ^uint64(0)); e == nil {
			t.Fatal(s)
		}
	}
	for s, want := range map[string]uint64{"0": 0, "019": 19, "0xff": 255, "0XFF": 255, "18446744073709551615": ^uint64(0)} {
		if n, e := Uint(s, ^uint64(0)); e != nil || n != want {
			t.Fatal(s, n, e)
		}
	}
}

func TestOutputPresenceConflicts(t *testing.T) {
	for _, a := range [][]string{args("--pcap", "x"), args("--pcap="), append(args()[:len(args())-1], "--hex=false", "--pcap", "x")} {
		if _, e := Parse(a, io.Discard); e == nil {
			t.Fatal(a)
		}
	}
}
