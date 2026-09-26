package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
)

type Reader struct {
	r     io.Reader
	order binary.ByteOrder
	nanos bool
	snap  uint32
}
type Record struct {
	Micros         uint64
	Frame          []byte
	OriginalLength uint32
}

func NewReader(r io.Reader) (*Reader, error) {
	h := make([]byte, 24)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, fmt.Errorf("PCAP header: %w", err)
	}
	p := &Reader{r: r}
	switch binary.LittleEndian.Uint32(h[:4]) {
	case 0xa1b2c3d4:
		p.order = binary.LittleEndian
	case 0xd4c3b2a1:
		p.order = binary.BigEndian
	case 0xa1b23c4d:
		p.order = binary.LittleEndian
		p.nanos = true
	case 0x4d3cb2a1:
		p.order = binary.BigEndian
		p.nanos = true
	default:
		return nil, fmt.Errorf("expected classic PCAP (pcapng is not supported)")
	}
	if p.order.Uint16(h[4:]) != 2 || p.order.Uint16(h[6:]) != 4 {
		return nil, fmt.Errorf("unsupported PCAP version")
	}
	if p.order.Uint32(h[20:]) != 1 {
		return nil, fmt.Errorf("PCAP link type must be Ethernet (1)")
	}
	p.snap = p.order.Uint32(h[16:])
	if p.snap == 0 {
		return nil, fmt.Errorf("zero PCAP snaplen")
	}
	return p, nil
}
func (r *Reader) Next() (Record, error) {
	var h [16]byte
	if _, err := io.ReadFull(r.r, h[:]); err != nil {
		return Record{}, err
	}
	sec, frac, n, original := r.order.Uint32(h[:]), r.order.Uint32(h[4:]), r.order.Uint32(h[8:]), r.order.Uint32(h[12:])
	limit := uint32(1_000_000)
	if r.nanos {
		limit = 1_000_000_000
	}
	if frac >= limit {
		return Record{}, fmt.Errorf("PCAP timestamp fraction out of range")
	}
	// Bound allocations independently of untrusted snaplen/record declarations.
	if n > r.snap || n > SnapLen || n > original {
		return Record{}, fmt.Errorf("invalid/oversize PCAP captured length %d", n)
	}
	if n != original {
		return Record{}, fmt.Errorf("truncated PCAP capture: captured=%d original=%d", n, original)
	}
	if r.nanos {
		frac /= 1000
	}
	p := Record{Micros: uint64(sec)*1_000_000 + uint64(frac), Frame: make([]byte, n), OriginalLength: original}
	if _, err := io.ReadFull(r.r, p.Frame); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Record{}, fmt.Errorf("PCAP frame: %w", err)
	}
	return p, nil
}
