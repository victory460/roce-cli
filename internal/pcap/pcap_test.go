package pcap

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

type failWriter struct{ err error }

func (w failWriter) Write([]byte) (int, error) { return 0, w.err }
func TestEncoding(t *testing.T) {
	var b bytes.Buffer
	w, e := New(&b)
	if e != nil {
		t.Fatal(e)
	}
	if e = w.WriteFrame(1234567, []byte{1, 2, 3}); e != nil {
		t.Fatal(e)
	}
	p := b.Bytes()
	if len(p) != 43 || le.Uint32(p) != 0xa1b2c3d4 || le.Uint16(p[4:]) != 2 || le.Uint16(p[6:]) != 4 || le.Uint32(p[16:]) != SnapLen || le.Uint32(p[20:]) != 1 || le.Uint32(p[24:]) != 1 || le.Uint32(p[28:]) != 234567 || le.Uint32(p[32:]) != 3 || le.Uint32(p[36:]) != 3 || !bytes.Equal(p[40:], []byte{1, 2, 3}) {
		t.Fatalf("%x", p)
	}
	if e = w.WriteFrame(4294967296000000, nil); e == nil {
		t.Fatal("overflow")
	}
	if e = w.WriteFrame(0, make([]byte, SnapLen+1)); e == nil {
		t.Fatal("oversize")
	}
}
func TestWriteErrors(t *testing.T) {
	if _, e := New(shortWriter{}); !errors.Is(e, io.ErrShortWrite) {
		t.Fatal(e)
	}
	boom := errors.New("disk full")
	if _, e := New(failWriter{boom}); !errors.Is(e, boom) {
		t.Fatal(e)
	}
	w := &Writer{shortWriter{}}
	if e := w.WriteFrame(0, []byte{1}); !errors.Is(e, io.ErrShortWrite) {
		t.Fatal(e)
	}
	// Header succeeds but frame write fails.
	w = &Writer{&afterHeader{}}
	if e := w.WriteFrame(0, []byte{1}); !errors.Is(e, io.ErrShortWrite) {
		t.Fatal(e)
	}
}

type afterHeader struct{ called bool }

func (w *afterHeader) Write(p []byte) (int, error) {
	if w.called {
		return 0, nil
	}
	w.called = true
	return len(p), nil
}
