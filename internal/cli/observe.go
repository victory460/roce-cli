package cli

import (
	"flag"
	"fmt"
	"io"
	"time"

	"roce-cli/internal/config"
)

func parseObserve(c config.Config, args []string, out io.Writer) (config.Config, error) {
	fs := flag.NewFlagSet(c.Command, flag.ContinueOnError)
	fs.SetOutput(out)
	values := map[string]*value{}
	add := func(name, def, help string, boolean bool) {
		v := &value{text: def, boolean: boolean}
		values[name] = v
		fs.Var(v, name, help)
	}
	add("pcap", "", "inspect: input file; receive: optional capture file (not stdout)", false)
	add("port", "4791", "RoCE UDP destination port", false)
	add("vxlan-port", "4789", "VXLAN UDP destination port (different from --port)", false)
	add("dqpn", "", "optional destination QPN filter (24 bits)", false)
	add("json", "false", "write one JSON object per result", true)
	add("strict", "false", "fail on invalid/malformed/unsupported packets or zero matches", true)
	add("count", "", "stop after N decoded matching frames (receive default: 1; inspect default: all)", false)
	if c.Command == "receive" {
		add("interface", "", "required Linux Ethernet interface", false)
		add("duration", "", "positive capture duration, e.g. 10s", false)
		add("continuous", "false", "capture until interrupted", true)
		add("overwrite", "false", "allow overwriting capture file", true)
	}
	fs.Usage = func() {
		fmt.Fprintf(out, "Usage: roce-cli %s [flags]\n", c.Command)
		if c.Command == "receive" {
			fmt.Fprintln(out, "Listen first; wait for 'ready', then start the sender. Incoming frames only; no QP or ACK handling.")
		} else {
			fmt.Fprintln(out, "Requires --pcap FILE. Reads classic Ethernet PCAP; no privileges or network access.")
		}
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}
	s := func(k string) string {
		if v := values[k]; v != nil {
			return v.text
		}
		return ""
	}
	has := func(k string) bool { return values[k] != nil && values[k].seen }
	n := func(k string, max uint64) (uint64, error) {
		x, e := Uint(s(k), max)
		if e != nil {
			return 0, fmt.Errorf("--%s: %w", k, e)
		}
		return x, nil
	}
	port, e := n("port", 65535)
	if e != nil {
		return c, e
	}
	vx, e := n("vxlan-port", 65535)
	if e != nil {
		return c, e
	}
	c.Port = uint16(port)
	c.VXLANPort = uint16(vx)
	if port == vx {
		return c, fmt.Errorf("--port and --vxlan-port must differ")
	}
	if has("dqpn") {
		q, e := n("dqpn", 0xffffff)
		if e != nil {
			return c, e
		}
		c.DQPN = uint32(q)
		c.FilterDQPN = true
	}
	c.JSON = s("json") == "true"
	c.Strict = s("strict") == "true"
	c.PCAP = s("pcap")
	if c.Command == "inspect" {
		c.Count = 0
		if c.PCAP == "" || c.PCAP == "-" {
			return c, fmt.Errorf("inspect requires --pcap with a regular file path")
		}
	}
	if has("count") {
		c.Count, e = n("count", ^uint64(0))
		if e != nil {
			return c, e
		}
		if c.Count == 0 {
			return c, fmt.Errorf("--count must be positive")
		}
	}
	if c.Command == "receive" {
		c.Interface = s("interface")
		if c.Interface == "" {
			return c, fmt.Errorf("receive requires --interface")
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
		c.Continuous = s("continuous") == "true"
		if has("continuous") && !c.Continuous {
			return c, fmt.Errorf("--continuous must be true when specified")
		}
		if has("duration") {
			c.Duration, e = time.ParseDuration(s("duration"))
			if e != nil || c.Duration <= 0 {
				return c, fmt.Errorf("--duration requires a positive Go duration")
			}
		}
		if c.PCAP == "-" || (has("pcap") && c.PCAP == "") {
			return c, fmt.Errorf("receive --pcap requires a file path; stdout contains decoded results")
		}
		c.Overwrite = s("overwrite") == "true"
		if has("overwrite") && c.PCAP == "" {
			return c, fmt.Errorf("--overwrite requires --pcap FILE")
		}
	}
	return c, nil
}
