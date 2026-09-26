package app

import (
	"bytes"
	"context"
	"errors"
	"net"
	"roce-cli/internal/config"
	"roce-cli/internal/sender"
	"strings"
	"testing"
	"time"
)

type fakeSender struct {
	frames   [][]byte
	closed   bool
	failAt   int
	cancel   context.CancelFunc
	closeErr error
	block    bool
}

func (s *fakeSender) Send(ctx context.Context, p []byte) error {
	if s.block {
		<-ctx.Done()
		return ctx.Err()
	}
	if s.failAt > 0 && len(s.frames)+1 == s.failAt {
		return errors.New("send failed")
	}
	s.frames = append(s.frames, append([]byte{}, p...))
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}
func (s *fakeSender) Close() error { s.closed = true; return s.closeErr }
func sendArgs(extra ...string) []string {
	a := buildArgs()
	a[0] = "send"
	return append(append(a, "--interface", "test"), extra...)
}
func dependencies(s *fakeSender, opened *bool, mtu int) Dependencies {
	return Dependencies{
		Resolve: func(c config.Config) (config.Config, net.Interface, error) {
			if mtu > 0 && mtu < c.MTU {
				c.MTU = mtu
			}
			return c, net.Interface{Index: 1}, nil
		},
		Open: func(net.Interface) (sender.Sender, error) { *opened = true; return s, nil },
	}
}
func TestSendCountAndFailure(t *testing.T) {
	for _, fail := range []int{0, 3} {
		s := &fakeSender{failAt: fail}
		opened := false
		var out, err bytes.Buffer
		code := Run(context.Background(), sendArgs("--count", "4"), &out, &err, dependencies(s, &opened, 1500))
		want := 4
		if fail > 0 {
			want = 2
		}
		if len(s.frames) != want || !opened || !s.closed || out.Len() != 0 {
			t.Fatal(s, opened, out.String())
		}
		if fail == 0 && code != 0 || fail > 0 && code == 0 {
			t.Fatal(code, err.String())
		}
		if fail > 0 && !strings.Contains(err.String(), "submitted frames=2") {
			t.Fatal(err.String())
		}
	}
}
func TestSendPreflight(t *testing.T) {
	s := &fakeSender{}
	opened := false
	var err bytes.Buffer
	code := Run(context.Background(), sendArgs("--payload-hex", strings.Repeat("ff", 100)), &bytes.Buffer{}, &err, dependencies(s, &opened, 68))
	if code == 0 || opened {
		t.Fatal(code, opened, err.String())
	}
}
func TestSendCancellationAndDuration(t *testing.T) {
	for _, duration := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		s := &fakeSender{}
		a := sendArgs("--interval", "1h", "--continuous")
		if duration {
			a = sendArgs("--interval", "1h", "--duration", "10ms")
		} else {
			s.cancel = cancel
		}
		opened := false
		var err bytes.Buffer
		start := time.Now()
		code := Run(ctx, a, &bytes.Buffer{}, &err, dependencies(s, &opened, 1500))
		cancel()
		if time.Since(start) > time.Second || !s.closed || len(s.frames) != 1 {
			t.Fatal(s, err.String())
		}
		if duration && code != 0 || !duration && code != 130 {
			t.Fatal(code, err.String())
		}
	}
	// Backpressure cancellation must also reach the Send implementation.
	s := &fakeSender{block: true}
	opened := false
	var err bytes.Buffer
	if code := Run(context.Background(), sendArgs("--duration", "10ms"), &bytes.Buffer{}, &err, dependencies(s, &opened, 1500)); code != 0 || !s.closed || len(s.frames) != 0 {
		t.Fatal(code, s, err.String())
	}
}
func TestSendCloseFailure(t *testing.T) {
	s := &fakeSender{closeErr: errors.New("close failed")}
	opened := false
	var err bytes.Buffer
	if code := Run(context.Background(), sendArgs(), &bytes.Buffer{}, &err, dependencies(s, &opened, 1500)); code == 0 || !strings.Contains(err.String(), "submitted frames=1") {
		t.Fatal(code, err.String())
	}
}

func TestSendExactList(t *testing.T) {
	s := &fakeSender{}
	opened := false
	var err bytes.Buffer
	code := Run(context.Background(), sendArgs("--psn-list", "5,4,4,7"), &bytes.Buffer{}, &err, dependencies(s, &opened, 1500))
	if code != 0 || len(s.frames) != 4 {
		t.Fatal(code, err.String())
	}
	for i, want := range []byte{5, 4, 4, 7} {
		if s.frames[i][53] != want {
			t.Fatal(i, s.frames[i][53])
		}
	}
}
