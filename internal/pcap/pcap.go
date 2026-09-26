// Package pcap writes classic little-endian microsecond Ethernet PCAP streams.
package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

const SnapLen = 65535 + 18

var le = binary.LittleEndian

type Writer struct{ w io.Writer }

func write(w io.Writer, b []byte) error {
	n, e := w.Write(b)
	if e != nil {
		return e
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}
func New(w io.Writer) (*Writer, error) {
	h := make([]byte, 24)
	le.PutUint32(h, 0xa1b2c3d4)
	le.PutUint16(h[4:], 2)
	le.PutUint16(h[6:], 4)
	le.PutUint32(h[16:], SnapLen)
	le.PutUint32(h[20:], 1)
	if e := write(w, h); e != nil {
		return nil, e
	}
	return &Writer{w}, nil
}
func (w *Writer) WriteFrame(micros uint64, frame []byte) error {
	if micros/1_000_000 > math.MaxUint32 {
		return fmt.Errorf("PCAP timestamp overflow")
	}
	if len(frame) > SnapLen {
		return fmt.Errorf("frame exceeds PCAP snaplen")
	}
	h := make([]byte, 16)
	le.PutUint32(h, uint32(micros/1_000_000))
	le.PutUint32(h[4:], uint32(micros%1_000_000))
	le.PutUint32(h[8:], uint32(len(frame)))
	le.PutUint32(h[12:], uint32(len(frame)))
	if e := write(w.w, h); e != nil {
		return e
	}
	return write(w.w, frame)
}
