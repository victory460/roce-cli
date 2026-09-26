package packet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

var standardPorts = DecodeOptions{Port: 4791, VXLANPort: 4789}

func TestDecodeScapyVectors(t *testing.T) {
	raw, e := os.ReadFile("../../testdata/vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors []struct {
		Template, Payload, Hex string
		VXLAN                  bool
	}
	if e = json.Unmarshal(raw, &vectors); e != nil {
		t.Fatal(e)
	}
	for _, v := range vectors {
		frame, _ := hex.DecodeString(v.Hex)
		r, e := Decode(frame, standardPorts)
		if e != nil || !r.Valid || r.Template != v.Template || r.PayloadLength != len(v.Payload)/2 || r.DQPN != 0x123456 {
			t.Fatalf("%+v %v", r, e)
		}
		if v.VXLAN && (r.Outer == nil || r.VNI != 100 || r.Outer.ECN != 3 || r.Inner.ECN != 2 || r.Inner.VLAN != 0 || r.Outer.VLAN != 4094) {
			t.Fatal(r)
		}
		if v.Template == "write-only" && (*r.RemoteAddr != 0x0102030405060708 || *r.RKey != 0x87654321) {
			t.Fatal(r)
		}
		if v.Template == "cnp" && (r.PSN != 0 || r.AckRequest) {
			t.Fatal(r)
		}
		// Every truncated prefix must be handled without a panic; full IP is
		// allowed to omit only Ethernet minimum-frame padding.
		for n := 0; n < len(frame); n++ {
			_, _ = Decode(frame[:n], standardPorts)
		}
	}
}
func TestDecodeValidationAndClassification(t *testing.T) {
	c := base()
	c.Payload = []byte{1, 2, 3}
	c.BadICRC = true
	r, e := Decode(build(t, c), standardPorts)
	if e != nil || r.Valid || r.ICRC != "invalid" || r.Inner.UDPChecksum != "valid" {
		t.Fatal(r, e)
	}
	c.BadICRC = false
	c.Inner.ZeroChecksum = true
	r, e = Decode(build(t, c), standardPorts)
	if e != nil || !r.Valid || r.Inner.UDPChecksum != "disabled" {
		t.Fatal(r, e)
	}
	p := build(t, c)
	p[24] ^= 1 // IPv4 checksum byte, masked from ICRC.
	r, e = Decode(p, standardPorts)
	if e != nil || r.Valid || r.ICRC != "valid" || r.Inner.IPv4Checksum != "invalid" {
		t.Fatal(r, e)
	}
	p = build(t, c)
	p[42] = 0xff
	if _, e = Decode(p, standardPorts); !errors.Is(e, ErrUnsupported) {
		t.Fatal(e)
	}
	p = build(t, c)
	p[23] = 6
	if _, e = Decode(p, standardPorts); !errors.Is(e, ErrUnrelated) {
		t.Fatal(e)
	}
	p = build(t, c)
	p[20] = 0x20
	if _, e = Decode(p, standardPorts); !errors.Is(e, ErrUnsupported) {
		t.Fatal(e)
	}
	p = build(t, c)
	p[38] = 0
	if _, e = Decode(p, standardPorts); e != nil {
		t.Fatal(e)
	} // length < 256, unchanged.
	p[39]++
	if _, e = Decode(p, standardPorts); e == nil {
		t.Fatal("bad UDP length")
	}
	c.Inner.DstPort = 1234
	p = build(t, c)
	if _, e = Decode(p, standardPorts); !errors.Is(e, ErrUnrelated) {
		t.Fatal(e)
	}
	if r, e = Decode(p, DecodeOptions{1234, 4789}); e != nil || !r.Valid {
		t.Fatal(r, e)
	}
}
func FuzzDecode(f *testing.F) {
	data, _ := os.ReadFile("../../testdata/vectors.json")
	var vectors []struct{ Hex string }
	_ = json.Unmarshal(data, &vectors)
	for _, v := range vectors {
		p, _ := hex.DecodeString(v.Hex)
		f.Add(p)
	}
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{255}, 64))
	f.Fuzz(func(t *testing.T, p []byte) {
		r, e := Decode(p, standardPorts)
		if e == nil && r.Template == "" {
			t.Fatal("decoded without template")
		}
	})
}

func TestPortFilterPrecedesUnsupportedLayout(t *testing.T) {
	p := build(t, base())
	// Add four bytes of IPv4 options, shifting the otherwise readable UDP header.
	withOptions := append([]byte{}, p[:34]...)
	withOptions = append(withOptions, 1, 1, 1, 1)
	withOptions = append(withOptions, p[34:]...)
	withOptions[14] = 0x46
	be.PutUint16(withOptions[16:18], be.Uint16(p[16:18])+4)
	be.PutUint16(withOptions[40:42], 53)
	clear(withOptions[24:26])
	be.PutUint16(withOptions[24:26], checksum(withOptions[14:38]))
	if _, e := Decode(withOptions, standardPorts); !errors.Is(e, ErrUnrelated) {
		t.Fatal(e)
	}
	be.PutUint16(withOptions[40:42], 4791)
	if _, e := Decode(withOptions, standardPorts); !errors.Is(e, ErrUnsupported) {
		t.Fatal(e)
	}
	// First UDP fragment to an unrelated port is still classifiable.
	p = build(t, base())
	be.PutUint16(p[36:38], 53)
	p[20] = 0x20
	if _, e := Decode(p, standardPorts); !errors.Is(e, ErrUnrelated) {
		t.Fatal(e)
	}
}
