package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestReaderFormats(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, nanos := range []bool{false, true} {
			h := make([]byte, 40)
			magic := uint32(0xa1b2c3d4)
			frac := uint32(123456)
			if nanos {
				magic = 0xa1b23c4d
				frac = 123456789
			}
			order.PutUint32(h, magic)
			order.PutUint16(h[4:], 2)
			order.PutUint16(h[6:], 4)
			order.PutUint32(h[16:], 262144)
			order.PutUint32(h[20:], 1)
			order.PutUint32(h[24:], 2)
			order.PutUint32(h[28:], frac)
			order.PutUint32(h[32:], 3)
			order.PutUint32(h[36:], 3)
			r, e := NewReader(bytes.NewReader(append(h, 1, 2, 3)))
			if e != nil {
				t.Fatal(e)
			}
			p, e := r.Next()
			if e != nil || p.Micros != 2123456 || !bytes.Equal(p.Frame, []byte{1, 2, 3}) {
				t.Fatal(p, e)
			}
			if _, e = r.Next(); e != io.EOF {
				t.Fatal(e)
			}
		}
	}
}
func TestReaderRejectsCorruption(t *testing.T) {
	var b bytes.Buffer
	w, _ := New(&b)
	_ = w.WriteFrame(0, []byte{1, 2, 3})
	good := b.Bytes()
	for _, mutate := range []func([]byte){func(p []byte) { le.PutUint32(p[32:], ^uint32(0)) }, func(p []byte) { le.PutUint32(p[36:], 4) }, func(p []byte) { le.PutUint32(p[28:], 1000000) }} {
		p := bytes.Clone(good)
		mutate(p)
		r, e := NewReader(bytes.NewReader(p))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = r.Next(); e == nil {
			t.Fatal("accepted invalid record")
		}
	}
	for _, n := range []int{25, 39, 40, 41, 42} {
		r, e := NewReader(bytes.NewReader(good[:n]))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = r.Next(); !errors.Is(e, io.ErrUnexpectedEOF) {
			t.Fatalf("n=%d: %v", n, e)
		}
	}
	for _, mutate := range []func([]byte){func(p []byte) { p[0] = 0 }, func(p []byte) { p[4] = 3 }, func(p []byte) { p[20] = 113 }, func(p []byte) { clear(p[16:20]) }} {
		p := bytes.Clone(good)
		mutate(p)
		if _, e := NewReader(bytes.NewReader(p)); e == nil {
			t.Fatal("accepted invalid header")
		}
	}
}
