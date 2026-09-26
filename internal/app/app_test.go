package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func buildArgs(extra ...string) []string {
	return append(strings.Fields("build --src-mac 02:00:00:00:00:01 --dst-mac 02:00:00:00:00:02 --src-ip 192.0.2.1 --dst-ip 192.0.2.2 --dqpn 0x123"), extra...)
}
func invoke(a []string) (int, []byte, string) {
	var out, err bytes.Buffer
	code := Run(context.Background(), a, &out, &err, Dependencies{})
	return code, out.Bytes(), err.String()
}
func TestBuildOutputAndDeterminism(t *testing.T) {
	a := buildArgs("--pcap", "-", "--psn-list", "100,101,101,103,102", "--interval", "100ms")
	code, p, summary := invoke(a)
	if code != 0 || !strings.Contains(summary, "generated frames=5") || !strings.Contains(summary, "icrc=valid") {
		t.Fatal(code, summary)
	}
	_, q, _ := invoke(a)
	if !bytes.Equal(p, q) {
		t.Fatal("nondeterministic")
	}
	le := binary.LittleEndian
	off := 24
	for i, psn := range []uint32{100, 101, 101, 103, 102} {
		if le.Uint32(p[off+4:]) != uint32(i)*100000 {
			t.Fatal("timestamp")
		}
		n := int(le.Uint32(p[off+8:]))
		frame := p[off+16 : off+16+n]
		if binary.BigEndian.Uint32(frame[50:54])&0xffffff != psn {
			t.Fatal("PSN")
		}
		off += 16 + n
	}
	if off != len(p) {
		t.Fatal("trailing bytes")
	}
	code, p, summary = invoke(buildArgs("--hex", "--count", "2"))
	if code != 0 || !strings.Contains(summary, "generated frames=2") {
		t.Fatal(summary)
	}
	lines := strings.Fields(string(p))
	if len(lines) != 2 {
		t.Fatal(string(p))
	}
	for _, line := range lines {
		if _, e := hex.DecodeString(line); e != nil {
			t.Fatal(e)
		}
	}
}
func TestInvalidInputsHaveNoSideEffects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.pcap")
	for _, extra := range [][]string{{"--count", "0"}, {"--payload-hex", strings.Repeat("ff", 1500)}, {"--interval", "1ns"}, {"--unknown"}, {"--psn-list", "1,2", "--count", "2"}} {
		code, _, _ := invoke(buildArgs(append([]string{"--pcap", path}, extra...)...))
		if code == 0 {
			t.Fatal(extra)
		}
		if _, e := os.Stat(path); !os.IsNotExist(e) {
			t.Fatal("created file", e)
		}
	}
	if e := os.WriteFile(path, []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	code, _, _ := invoke(buildArgs("--pcap", path))
	if code == 0 {
		t.Fatal("overwrote")
	}
	p, _ := os.ReadFile(path)
	if string(p) != "keep" {
		t.Fatal(string(p))
	}
	code, _, s := invoke(buildArgs("--pcap", path, "--overwrite", "--payload-hex", strings.Repeat("ff", 1500)))
	if code == 0 {
		t.Fatal(s)
	}
	p, _ = os.ReadFile(path)
	if string(p) != "keep" {
		t.Fatal("invalid overwrite truncated file")
	}
	code, _, s = invoke(buildArgs("--pcap", path, "--overwrite"))
	if code != 0 {
		t.Fatal(s)
	}
	p, _ = os.ReadFile(path)
	if len(p) != 100 {
		t.Fatal(len(p))
	}
}

type shortOutput struct{}

func (shortOutput) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestOutputErrorsAndCancellation(t *testing.T) {
	for _, mode := range [][]string{{"--hex"}, {"--pcap", "-"}} {
		var err bytes.Buffer
		code := Run(context.Background(), buildArgs(mode...), shortOutput{}, &err, Dependencies{})
		if code == 0 || !strings.Contains(err.String(), "short write") || !strings.Contains(err.String(), "frames=0") {
			t.Fatal(code, err.String())
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var err bytes.Buffer
	code := Run(ctx, buildArgs("--hex"), io.Discard, &err, Dependencies{})
	if code != 130 || !strings.Contains(err.String(), "status=interrupted") {
		t.Fatal(code, err.String())
	}
}

type failedOutput struct{}

func (failedOutput) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestVersionOutputFailure(t *testing.T) {
	for _, w := range []io.Writer{shortOutput{}, failedOutput{}} {
		var stderr bytes.Buffer
		if code := Run(context.Background(), []string{"--version"}, w, &stderr, Dependencies{}); code != 1 {
			t.Fatalf("failed version output returned %d, stderr=%s", code, stderr.String())
		}
	}
}
