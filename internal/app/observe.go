package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"roce-cli/internal/config"
	"roce-cli/internal/packet"
	"roce-cli/internal/pcap"
	"roce-cli/internal/receiver"
)

type observationStats struct {
	seen, matched, valid, invalid, ignored, malformed, unsupported, saved uint64
	status                                                                string
}
type event struct {
	Index     uint64         `json:"index"`
	Timestamp string         `json:"timestamp"`
	Packet    *packet.Report `json:"packet,omitempty"`
	Error     string         `json:"error,omitempty"`
}

func observe(ctx context.Context, c config.Config, stdout, stderr io.Writer, deps Dependencies) int {
	st := observationStats{status: "complete"}
	err := observeFrames(ctx, c, stdout, stderr, deps, &st)
	code := 0
	if err != nil {
		code = 1
		st.status = "error"
		if errors.Is(err, context.Canceled) {
			code = 130
			st.status = "interrupted"
		}
		fmt.Fprintln(stderr, "error:", err)
	}
	if code == 0 && c.Strict && (st.matched == 0 || st.invalid > 0 || st.malformed > 0 || st.unsupported > 0) {
		code = 1
		st.status = "validation-failed"
	}
	verb := "inspected"
	if c.Command == "receive" {
		verb = "received"
	}
	fmt.Fprintf(stderr, "%s frames=%d valid=%d invalid=%d ignored=%d malformed=%d unsupported=%d saved=%d status=%s\n", verb, st.matched, st.valid, st.invalid, st.ignored, st.malformed, st.unsupported, st.saved, st.status)
	return code
}

func observeFrames(ctx context.Context, c config.Config, stdout, stderr io.Writer, deps Dependencies, st *observationStats) (err error) {
	var next func(context.Context) (receiver.Frame, error)
	if c.Command == "inspect" {
		info, e := os.Stat(c.PCAP)
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("inspect requires a regular PCAP file")
		}
		file, e := os.Open(c.PCAP)
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, file.Close()) }()
		reader, e := pcap.NewReader(file)
		if e != nil {
			return e
		}
		next = func(ctx context.Context) (receiver.Frame, error) {
			if e := ctx.Err(); e != nil {
				return receiver.Frame{}, e
			}
			r, e := reader.Next()
			if e != nil {
				return receiver.Frame{}, e
			}
			return receiver.Frame{Bytes: r.Frame, Timestamp: time.Unix(int64(r.Micros/1_000_000), int64(r.Micros%1_000_000)*1000)}, nil
		}
	} else {
		if e := ctx.Err(); e != nil {
			return e
		}
		if deps.OpenReceiver == nil {
			deps.OpenReceiver = receiver.Open
		}
		source, e := deps.OpenReceiver(c.Interface)
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, source.Close()) }()
		next = source.Receive
	}
	var capture *pcap.Writer
	if c.Command == "receive" && c.PCAP != "" {
		flags := os.O_CREATE | os.O_WRONLY | os.O_EXCL
		if c.Overwrite {
			flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		}
		file, e := os.OpenFile(c.PCAP, flags, 0644)
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, file.Close()) }()
		capture, e = pcap.New(file)
		if e != nil {
			return e
		}
	}
	runctx := ctx
	if c.Duration > 0 {
		var cancel context.CancelFunc
		runctx, cancel = context.WithTimeout(ctx, c.Duration)
		defer cancel()
	}
	out, closeOut, e := prepareOutput(runctx, stdout)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, closeOut()) }()
	if c.Command == "receive" {
		fmt.Fprintf(stderr, "ready interface=%s port=%d vxlan-port=%d direction=incoming\n", c.Interface, c.Port, c.VXLANPort)
	}
	finish := func(e error) error {
		if c.Duration > 0 && errors.Is(e, context.DeadlineExceeded) && ctx.Err() == nil {
			st.status = "duration-complete"
			return nil
		}
		return e
	}
	limited := c.Count > 0 && !c.Continuous && c.Duration == 0
	for !limited || st.matched < c.Count {
		frame, e := next(runctx)
		if errors.Is(e, io.EOF) && c.Command == "inspect" {
			return nil
		}
		if e != nil {
			return finish(e)
		}
		st.seen++
		report, e := packet.Decode(frame.Bytes, packet.DecodeOptions{Port: c.Port, VXLANPort: c.VXLANPort})
		if errors.Is(e, packet.ErrUnrelated) {
			st.ignored++
			continue
		}
		item := event{Index: st.seen, Timestamp: frame.Timestamp.UTC().Format(time.RFC3339Nano)}
		if e != nil {
			if errors.Is(e, packet.ErrUnsupported) {
				st.unsupported++
			} else {
				st.malformed++
			}
			item.Error = e.Error()
		} else {
			if c.FilterDQPN && report.DQPN != c.DQPN {
				st.ignored++
				continue
			}
			st.matched++
			if report.Valid {
				st.valid++
			} else {
				st.invalid++
			}
			item.Packet = &report
			if capture != nil {
				micros := frame.Timestamp.UnixMicro()
				if micros < 0 {
					return fmt.Errorf("capture timestamp precedes Unix epoch")
				}
				if e = capture.WriteFrame(uint64(micros), frame.Bytes); e != nil {
					return e
				}
				st.saved++
			}
		}
		if e = writeEvent(out, c.JSON, item); e != nil {
			// A deadline while waiting for the next frame is normal completion;
			// interrupting an output record is an I/O failure, not a successful run.
			return e
		}
	}
	return nil
}

func writeEvent(w io.Writer, jsonOutput bool, item event) error {
	if jsonOutput {
		p, e := json.Marshal(item)
		if e != nil {
			return e
		}
		return writeText(w, string(p)+"\n")
	}
	if item.Error != "" {
		return writeText(w, fmt.Sprintf("frame=%d time=%s error=%q\n", item.Index, item.Timestamp, item.Error))
	}
	p := item.Packet
	text := fmt.Sprintf("frame=%d time=%s template=%s encap=%s dqpn=0x%x psn=0x%x payload=%d valid=%t icrc=%s", item.Index, item.Timestamp, p.Template, p.Encap, p.DQPN, p.PSN, p.PayloadLength, p.Valid, p.ICRC)
	layer := func(name string, l packet.LayerReport) string {
		return fmt.Sprintf(" %ssrc=%s:%d %sdst=%s:%d %sdscp=%d %secn=%d %svlan=%d %spcp=%d %sip-checksum=%s %sudp-checksum=%s", name, l.SrcIP, l.SrcPort, name, l.DstIP, l.DstPort, name, l.DSCP, name, l.ECN, name, l.VLAN, name, l.PCP, name, l.IPv4Checksum, name, l.UDPChecksum)
	}
	text += layer("", p.Inner)
	if p.Outer != nil {
		text += fmt.Sprintf(" vni=%d", p.VNI) + layer("outer-", *p.Outer)
	}
	if p.RemoteAddr != nil {
		text += fmt.Sprintf(" remote-addr=0x%x rkey=0x%x", *p.RemoteAddr, *p.RKey)
	}
	if len(p.Issues) > 0 {
		text += fmt.Sprintf(" issues=%q", strings.Join(p.Issues, "; "))
	}
	return writeText(w, text+"\n")
}
