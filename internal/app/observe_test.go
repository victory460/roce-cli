package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"roce-cli/internal/cli"
	"roce-cli/internal/packet"
	"roce-cli/internal/pcap"
	"roce-cli/internal/receiver"
	"roce-cli/internal/sequence"
)

func observedFrame(t *testing.T, bad bool) receiver.Frame {
	t.Helper()
	a := buildArgs("--hex")
	if bad {
		a = append(a, "--bad-icrc")
	}
	c, e := cli.Parse(a, io.Discard)
	if e != nil {
		t.Fatal(e)
	}
	p, e := packet.Build(c, sequence.At(c, 0))
	if e != nil {
		t.Fatal(e)
	}
	return receiver.Frame{Bytes: p, Timestamp: time.Unix(100, 123456000)}
}

type fakeReceiver struct {
	frames []receiver.Frame
	closed bool
	err    error
}

func (r *fakeReceiver) Receive(ctx context.Context) (receiver.Frame, error) {
	if len(r.frames) > 0 {
		f := r.frames[0]
		r.frames = r.frames[1:]
		return f, nil
	}
	if r.err != nil {
		return receiver.Frame{}, r.err
	}
	<-ctx.Done()
	return receiver.Frame{}, ctx.Err()
}
func (r *fakeReceiver) Close() error { r.closed = true; return nil }
func receiveDeps(r *fakeReceiver) Dependencies {
	return Dependencies{OpenReceiver: func(string) (receiver.Receiver, error) { return r, nil }}
}

func TestReceiveCaptureAndInspect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcap")
	r := &fakeReceiver{frames: []receiver.Frame{observedFrame(t, false), observedFrame(t, true)}}
	var stdout, stderr bytes.Buffer
	a := []string{"receive", "--interface", "test", "--count", "2", "--pcap", path, "--json", "--strict"}
	code := Run(context.Background(), a, &stdout, &stderr, receiveDeps(r))
	if code != 1 || !r.closed || !strings.Contains(stderr.String(), "ready interface=test") || !strings.Contains(stderr.String(), "frames=2 valid=1 invalid=1") || !strings.Contains(stderr.String(), "saved=2") {
		t.Fatal(code, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 {
		t.Fatal(stdout.String())
	}
	for i, line := range lines {
		var v event
		if e := json.Unmarshal([]byte(line), &v); e != nil || v.Packet == nil || v.Packet.Valid != (i == 0) {
			t.Fatal(v, e)
		}
	}
	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"inspect", "--pcap", path, "--strict"}, &stdout, &stderr, Dependencies{})
	if code != 1 || !strings.Contains(stderr.String(), "frames=2 valid=1 invalid=1") || !strings.Contains(stdout.String(), "icrc=invalid") {
		t.Fatal(code, stdout.String(), stderr.String())
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	reader, e := pcap.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	record, e := reader.Next()
	if e != nil || record.Micros != 100123456 {
		t.Fatal(record, e)
	}
}
func TestObserveFiltersAndErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed.pcap")
	var p bytes.Buffer
	w, _ := pcap.New(&p)
	f := observedFrame(t, false)
	_ = w.WriteFrame(0, f.Bytes)
	arp := bytes.Clone(f.Bytes)
	arp[12] = 8
	arp[13] = 6
	_ = w.WriteFrame(1, arp)
	unsupported := bytes.Clone(f.Bytes)
	unsupported[42] = 0xff
	_ = w.WriteFrame(2, unsupported)
	_ = w.WriteFrame(3, []byte{1, 2})
	if e := os.WriteFile(path, p.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	var out, err bytes.Buffer
	if code := Run(context.Background(), []string{"inspect", "--pcap", path, "--strict"}, &out, &err, Dependencies{}); code != 1 || !strings.Contains(err.String(), "frames=1 valid=1 invalid=0 ignored=1 malformed=1 unsupported=1") {
		t.Fatal(code, err.String())
	}
	out.Reset()
	err.Reset()
	if code := Run(context.Background(), []string{"inspect", "--pcap", path, "--dqpn", "0", "--strict"}, &out, &err, Dependencies{}); code != 1 || !strings.Contains(err.String(), "frames=0") {
		t.Fatal(code, err.String())
	}
	// A complete record header with missing frame bytes is not a clean EOF.
	if e := os.WriteFile(path, p.Bytes()[:40], 0600); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	err.Reset()
	if code := Run(context.Background(), []string{"inspect", "--pcap", path}, &out, &err, Dependencies{}); code != 1 || !strings.Contains(err.String(), "unexpected EOF") {
		t.Fatal(code, err.String())
	}
}
func TestReceiveDurationCancelAndFailures(t *testing.T) {
	for _, strict := range []bool{false, true} {
		r := &fakeReceiver{}
		a := []string{"receive", "--interface", "test", "--duration", "10ms"}
		if strict {
			a = append(a, "--strict")
		}
		var err bytes.Buffer
		code := Run(context.Background(), a, io.Discard, &err, receiveDeps(r))
		want := 0
		if strict {
			want = 1
		}
		if code != want || !r.closed {
			t.Fatal(code, err.String())
		}
	}
	r := &fakeReceiver{err: errors.New("capture failed")}
	var err bytes.Buffer
	if code := Run(context.Background(), []string{"receive", "--interface", "test"}, io.Discard, &err, receiveDeps(r)); code != 1 || !r.closed {
		t.Fatal(code, err.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = &fakeReceiver{}
	err.Reset()
	if code := Run(ctx, []string{"receive", "--interface", "test"}, io.Discard, &err, receiveDeps(r)); code != 130 {
		t.Fatal(code, err.String())
	}
}
func TestReceiveProtectsCaptureFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keep.pcap")
	_ = os.WriteFile(path, []byte("keep"), 0600)
	r := &fakeReceiver{frames: []receiver.Frame{observedFrame(t, false)}}
	if code := Run(context.Background(), []string{"receive", "--interface", "test", "--pcap", path}, io.Discard, io.Discard, receiveDeps(r)); code != 1 || !r.closed {
		t.Fatal(code)
	}
	p, _ := os.ReadFile(path)
	if string(p) != "keep" {
		t.Fatal("overwrote file")
	}
}

type blockedEventWriter struct{ done chan struct{} }

func (w *blockedEventWriter) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		close(w.done)
	}
	return nil
}
func (w *blockedEventWriter) Write([]byte) (int, error) { <-w.done; return 0, os.ErrDeadlineExceeded }

func TestReceiveDurationDoesNotHideOutputFailure(t *testing.T) {
	r := &fakeReceiver{frames: []receiver.Frame{observedFrame(t, false)}}
	w := &blockedEventWriter{done: make(chan struct{})}
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"receive", "--interface", "test", "--duration", "10ms", "--strict", "--json"}, w, &stderr, receiveDeps(r))
	if code != 1 || !strings.Contains(stderr.String(), "status=error") || !r.closed {
		t.Fatal(code, stderr.String())
	}
}
