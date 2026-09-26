// Package app orchestrates generation and submission; dependencies can be replaced in tests.
package app

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"roce-cli/internal/cli"
	"roce-cli/internal/config"
	"roce-cli/internal/netutil"
	"roce-cli/internal/packet"
	"roce-cli/internal/pcap"
	"roce-cli/internal/receiver"
	"roce-cli/internal/sender"
	"roce-cli/internal/sequence"
	"time"
)

var Version = "dev"

type Dependencies struct {
	Resolve      func(config.Config) (config.Config, net.Interface, error)
	Open         func(net.Interface) (sender.Sender, error)
	OpenReceiver func(string) (receiver.Receiver, error)
}
type stats struct {
	frames, bytes uint64
	status        string
}

func Run(ctx context.Context, args []string, stdout, stderr io.Writer, deps Dependencies) int {
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		if err := writeText(stdout, Version+"\n"); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		return 0
	}
	c, e := cli.Parse(args, stderr)
	if errors.Is(e, flag.ErrHelp) {
		return 0
	}
	if e != nil {
		fmt.Fprintln(stderr, "error:", e)
		return 2
	}
	if c.Command == "receive" || c.Command == "inspect" {
		return observe(ctx, c, stdout, stderr, deps)
	}
	st := stats{status: "complete"}
	if c.Command == "build" {
		e = build(ctx, c, stdout, &st)
	} else {
		if deps.Resolve == nil {
			deps.Resolve = netutil.Resolve
		}
		if deps.Open == nil {
			deps.Open = sender.Open
		}
		e = send(ctx, &c, deps, &st)
	}
	code := 0
	if e != nil {
		code = 1
		st.status = "error"
		if errors.Is(e, context.Canceled) {
			code = 130
			st.status = "interrupted"
		}
		fmt.Fprintln(stderr, "error:", e)
	}
	verb := "generated"
	if c.Command == "send" {
		verb = "submitted"
	}
	icrc := "valid"
	if c.BadICRC {
		icrc = "bad"
	}
	fmt.Fprintf(stderr, "%s frames=%d bytes=%d status=%s template=%s encap=%s src=%s dst=%s dqpn=0x%x psn=0x%x src-port=%d dscp=%d ecn=%d icrc=%s\n", verb, st.frames, st.bytes, st.status, c.Template, c.Encap, c.Inner.SrcIP, c.Inner.DstIP, c.DQPN, sequence.At(c, 0).PSN, c.Inner.SrcPort, c.Inner.DSCP, c.Inner.ECN, icrc)
	return code
}
func build(ctx context.Context, c config.Config, stdout io.Writer, st *stats) (err error) {
	first, e := packet.Build(c, sequence.At(c, 0))
	if e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	w := stdout
	if c.PCAP != "" && c.PCAP != "-" {
		flags := os.O_CREATE | os.O_WRONLY | os.O_EXCL
		if c.Overwrite {
			flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		}
		f, e := os.OpenFile(c.PCAP, flags, 0644)
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, f.Close()) }()
		w = f
	}
	w, closeOutput, e := prepareOutput(ctx, w)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, closeOutput()) }()
	var pw *pcap.Writer
	if c.PCAP != "" {
		pw, e = pcap.New(w)
		if e != nil {
			return e
		}
	}
	for i := uint64(0); i < c.FrameCount(); i++ {
		if e = ctx.Err(); e != nil {
			return e
		}
		p := first
		if i > 0 {
			p, e = packet.Build(c, sequence.At(c, i))
			if e != nil {
				return e
			}
		}
		if pw != nil {
			e = pw.WriteFrame(i*uint64(c.Interval/time.Microsecond), p)
		} else {
			e = writeText(w, hex.EncodeToString(p)+"\n")
		}
		if e != nil {
			return e
		}
		st.frames++
		st.bytes += uint64(len(p))
	}
	return nil
}

// Text output follows the same short-write rules as binary PCAP output.
func writeText(w io.Writer, text string) error {
	n, err := io.WriteString(w, text)
	if err != nil {
		return err
	}
	if n != len(text) {
		return io.ErrShortWrite
	}
	return nil
}

func send(ctx context.Context, c *config.Config, deps Dependencies, st *stats) (err error) {
	resolved, iface, e := deps.Resolve(*c)
	if e != nil {
		return e
	}
	*c = resolved
	first, e := packet.Build(*c, sequence.At(*c, 0))
	if e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	s, e := deps.Open(iface)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, s.Close()) }()
	runctx := ctx
	if c.Duration > 0 {
		var cancel context.CancelFunc
		runctx, cancel = context.WithTimeout(ctx, c.Duration)
		defer cancel()
	}
	limited := !c.Continuous && c.Duration == 0
	finish := func(e error) error {
		if c.Duration > 0 && errors.Is(e, context.DeadlineExceeded) && ctx.Err() == nil {
			st.status = "duration-complete"
			return nil
		}
		return e
	}
	for i := uint64(0); !limited || i < c.FrameCount(); i++ {
		if e = runctx.Err(); e != nil {
			return finish(e)
		}
		p := first
		if i > 0 {
			p, e = packet.Build(*c, sequence.At(*c, i))
			if e != nil {
				return e
			}
		}
		if e = s.Send(runctx, p); e != nil {
			return finish(e)
		}
		st.frames++
		st.bytes += uint64(len(p))
		if limited && i == c.FrameCount()-1 {
			return nil
		}
		if c.Interval > 0 {
			timer := time.NewTimer(c.Interval)
			select {
			case <-runctx.Done():
				timer.Stop()
				return finish(runctx.Err())
			case <-timer.C:
			}
		}
	}
	return nil
}
