package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestObserveCLI(t *testing.T) {
	for _, args := range []string{"receive --interface eth0", "recv --interface eth0 --duration 1s --json --strict", "inspect --pcap x --dqpn 0 --count 2", "receive --interface eth0 --continuous --pcap x --overwrite", "inspect --pcap x --port 1234"} {
		if _, e := Parse(strings.Fields(args), io.Discard); e != nil {
			t.Fatal(args, e)
		}
	}
	for _, args := range []string{"receive", "inspect", "inspect --pcap -", "receive --interface eth0 --pcap -", "receive --interface eth0 --count 0", "receive --interface eth0 --count 1 --duration 1s", "receive --interface eth0 --duration 0", "receive --interface eth0 --continuous=false", "receive --interface eth0 --overwrite=false", "inspect --pcap x --interface eth0", "inspect --pcap x --duration 1s", "inspect --pcap x --port 4789", "inspect --pcap x --port 65536", "inspect --pcap x --dqpn 0x1000000", "receive --interface eth0 --payload-hex ab", "inspect --pcap x --json --json"} {
		if _, e := Parse(strings.Fields(args), io.Discard); e == nil {
			t.Fatal(args)
		}
	}
	c, e := Parse([]string{"inspect", "--pcap", "x"}, io.Discard)
	if e != nil || c.Count != 0 || c.Port != 4791 || c.VXLANPort != 4789 {
		t.Fatal(c, e)
	}
}
func TestCommandHelp(t *testing.T) {
	for _, command := range []string{"build", "send", "receive", "inspect"} {
		var out bytes.Buffer
		_, _ = Parse([]string{"help", command}, &out)
		if !strings.Contains(out.String(), "roce-cli "+command) {
			t.Fatal(out.String())
		}
	}
	var out bytes.Buffer
	_, _ = Parse([]string{"build", "--help"}, &out)
	if strings.Contains(out.String(), "-continuous") {
		t.Fatal("build lists send-only flags")
	}
	out.Reset()
	_, _ = Parse([]string{"send", "--help"}, &out)
	if strings.Contains(out.String(), "-pcap") {
		t.Fatal("send lists build-only flags")
	}
}
