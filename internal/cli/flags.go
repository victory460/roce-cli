// Flag registration is kept separate from parsing and semantic validation.
package cli

import (
	"flag"
	"fmt"
	"io"
	"strconv"
)

type value struct {
	text          string
	seen, boolean bool
}

func (v *value) String() string   { return v.text }
func (v *value) IsBoolFlag() bool { return v.boolean }
func (v *value) Set(s string) error {
	if v.seen {
		return fmt.Errorf("flag repeated")
	}
	v.seen = true
	if v.boolean {
		b, e := strconv.ParseBool(s)
		if e != nil {
			return e
		}
		s = strconv.FormatBool(b)
	}
	v.text = s
	return nil
}

func newFlagSet(command string, out io.Writer) (*flag.FlagSet, map[string]*value) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(out)
	values := map[string]*value{}
	add := func(name, def, help string, boolean bool) {
		v := &value{text: def, boolean: boolean}
		values[name] = v
		if command == "build" && (name == "interface" || name == "duration" || name == "continuous") {
			return
		}
		if command == "send" && (name == "pcap" || name == "hex" || name == "overwrite") {
			return
		}
		fs.Var(v, name, help)
	}
	fs.Usage = func() {
		fmt.Fprintf(out, "Usage: roce-cli %s [flags]\n", command)
		if command == "build" {
			fmt.Fprintln(out, "Required: --src-mac --dst-mac --src-ip --dst-ip --dqpn and exactly one of --pcap FILE | --hex.")
		} else {
			fmt.Fprintln(out, "Required: --interface --dst-mac --dst-ip --dqpn. Default: one frame. Raw Ethernet only; no QP setup.")
		}
		fs.PrintDefaults()
	}
	add("template", "send-only", "send-only | write-only | cnp", false)
	add("encap", "none", "none | vxlan", false)
	for _, prefix := range []string{"", "outer-"} {
		for _, name := range []string{"src-mac", "dst-mac", "src-ip", "dst-ip"} {
			add(prefix+name, "", "IPv4/Ethernet address", false)
		}
		sport, dport := "49152", "4791"
		if prefix != "" {
			sport, dport = "55000", "4789"
		}
		for _, d := range [][3]string{
			{"src-port", sport, "UDP source port 0..65535"},
			{"dst-port", dport, "UDP destination port 0..65535"},
			{"dscp", "0", "DSCP 0..63"},
			{"ecn", "0", "ECN 0..3"},
			{"ttl", "64", "TTL 1..255"},
			{"vlan-id", "", "VLAN 0..4094; omitted means untagged"},
			{"pcp", "0", "VLAN priority 0..7"},
			{"udp-checksum", "auto", "auto | zero"},
		} {
			add(prefix+d[0], d[1], d[2], false)
		}
	}
	for _, d := range [][3]string{
		{"dqpn", "", "destination QPN (required, 24 bits)"},
		{"psn", "0", "initial PSN (24 bits)"},
		{"psn-step", "1", "PSN increment (24 bits, wraps)"},
		{"psn-list", "", "exact comma-separated PSNs"},
		{"pkey", "0xffff", "16-bit partition key"},
		{"remote-addr", "", "64-bit WRITE address (required for write-only)"},
		{"rkey", "", "32-bit WRITE key (required for write-only)"},
		{"vni", "", "VXLAN VNI 1..0xffffff"},
		{"payload-hex", "", "even-length hexadecimal data"},
		{"mtu", "1500", "maximum outer IP length 68..65535"},
		{"count", "1", "positive frame count"},
		{"src-port-step", "0", "UDP source port increment (16 bits, wraps)"},
		{"interval", "0s", "minimum interval, Go duration format"},
		{"duration", "0s", "send for positive Go duration"},
		{"pcap", "", "PCAP file; - writes stdout"},
		{"interface", "", "Linux send interface"},
	} {
		add(d[0], d[1], d[2], false)
	}
	for _, d := range [][2]string{
		{"ack-request", "request ACK (data templates)"},
		{"bad-icrc", "flip ICRC bit 0; retain valid UDP checksum"},
		{"hex", "write one hex frame per line"},
		{"overwrite", "allow overwriting PCAP file"},
		{"continuous", "send until interrupted"},
	} {
		add(d[0], "false", d[1], true)
	}
	return fs, values
}
