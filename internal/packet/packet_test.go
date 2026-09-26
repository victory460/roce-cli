package packet

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"roce-cli/internal/config"
	"roce-cli/internal/sequence"
	"testing"
)

func base() config.Config {
	c := config.Defaults()
	c.DQPN = 0x123456
	c.PSN = 0xfffffe
	c.AckRequest = true
	c.Inner.SrcMAC, _ = net.ParseMAC("02:00:00:00:00:01")
	c.Inner.DstMAC, _ = net.ParseMAC("02:00:00:00:00:02")
	c.Inner.SrcIP = netip.MustParseAddr("192.0.2.1")
	c.Inner.DstIP = netip.MustParseAddr("192.0.2.2")
	c.Inner.DSCP = 24
	c.Inner.ECN = 2
	c.RemoteAddr = 0x0102030405060708
	c.RKey = 0x87654321
	return c
}
func build(t *testing.T, c config.Config) []byte {
	t.Helper()
	p, e := Build(c, sequence.At(c, 0))
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestScapyVectors(t *testing.T) {
	data, e := os.ReadFile("../../testdata/vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors []struct {
		Template, Payload, Hex string
		VXLAN                  bool
	}
	if e = json.Unmarshal(data, &vectors); e != nil {
		t.Fatal(e)
	}
	if len(vectors) != 22 {
		t.Fatalf("expected 22 vectors, got %d", len(vectors))
	}
	for _, v := range vectors {
		t.Run(v.Template+v.Payload+map[bool]string{true: "vxlan", false: "direct"}[v.VXLAN], func(t *testing.T) {
			c := base()
			c.Template = v.Template
			c.Payload, _ = hex.DecodeString(v.Payload)
			if c.Template == "cnp" {
				c.Inner.SrcPort = 0
				c.AckRequest = false
			}
			if v.VXLAN {
				c.Encap = "vxlan"
				c.VNI = 100
				c.Inner.VLAN = 0
				c.Inner.PCP = 7
				c.Outer.SrcMAC, _ = net.ParseMAC("02:00:00:00:01:01")
				c.Outer.DstMAC, _ = net.ParseMAC("02:00:00:00:01:02")
				c.Outer.SrcIP = netip.MustParseAddr("198.51.100.1")
				c.Outer.DstIP = netip.MustParseAddr("198.51.100.2")
				c.Outer.VLAN = 4094
				c.Outer.PCP = 3
				c.Outer.DSCP = 24
				c.Outer.ECN = 3
				c.Outer.TTL = 32
			}
			want, _ := hex.DecodeString(v.Hex)
			got := build(t, c)
			if !bytes.Equal(got, want) {
				t.Fatalf("wire mismatch\ngot  %x\nwant %x", got, want)
			}
		})
	}
}
func crcBytes(p []byte) []byte { ip := p[14:]; n := int(be.Uint16(ip[2:4])); return ip[n-4 : n] }
func assertChecksums(t *testing.T, p []byte) {
	t.Helper()
	ip := p[14:]
	ip = ip[:be.Uint16(ip[2:4])]
	if checksum(ip[:20]) != 0 {
		t.Fatal("bad IP checksum")
	}
	pseudo := append([]byte{}, ip[12:20]...)
	pseudo = append(pseudo, 0, 17, ip[24], ip[25])
	pseudo = append(pseudo, ip[20:]...)
	if checksum(pseudo) != 0 {
		t.Fatal("bad UDP checksum")
	}
}
func TestICRCInvariants(t *testing.T) {
	c := base()
	c.Payload = []byte{1, 2, 3}
	orig := build(t, c)
	for _, change := range []func(*config.Config){func(c *config.Config) { c.Inner.TTL = 1 }, func(c *config.Config) { c.Inner.DSCP = 63; c.Inner.ECN = 3 }, func(c *config.Config) { c.Inner.ZeroChecksum = true }} {
		x := c
		change(&x)
		if !bytes.Equal(crcBytes(orig), crcBytes(build(t, x))) {
			t.Fatal("masked field changed ICRC")
		}
	}
	for _, change := range []func(*config.Config){func(c *config.Config) { c.PSN++ }, func(c *config.Config) { c.Inner.SrcIP = netip.MustParseAddr("192.0.2.3") }, func(c *config.Config) { c.Payload = []byte{1, 2, 4} }, func(c *config.Config) { c.Inner.SrcPort++ }} {
		x := c
		change(&x)
		if bytes.Equal(crcBytes(orig), crcBytes(build(t, x))) {
			t.Fatal("unmasked field did not change ICRC")
		}
	}
	c.BadICRC = true
	bad := build(t, c)
	if binary.LittleEndian.Uint32(crcBytes(orig))^binary.LittleEndian.Uint32(crcBytes(bad)) != 1 {
		t.Fatal("bad-icrc must flip one bit")
	}
	assertChecksums(t, orig)
	assertChecksums(t, bad)
}
func TestMTUAndPadding(t *testing.T) {
	c := base()
	c.Payload = make([]byte, 1456)
	if len(build(t, c)) != 1514 {
		t.Fatal("exact MTU")
	}
	c.Payload = make([]byte, 1457)
	if _, e := Build(c, sequence.At(c, 0)); e == nil {
		t.Fatal("oversize accepted")
	}
	c.Payload = nil
	p := build(t, c)
	if len(p) != 60 || be.Uint16(p[16:18]) != 44 || !bytes.Equal(p[58:], []byte{0, 0}) {
		t.Fatalf("Ethernet padding: %x", p)
	}
	c.Payload = make([]byte, 65535)
	c.MTU = 65535
	if _, e := Build(c, sequence.At(c, 0)); e == nil {
		t.Fatal("IPv4 overflow accepted")
	}
}
func TestZeroUDPChecksumRepresentation(t *testing.T) {
	c := base()
	c.Inner.ZeroChecksum = true
	if be.Uint16(build(t, c)[40:42]) != 0 {
		t.Fatal("zero mode")
	}
	// Find the arithmetic-zero case independently; wire must use ffff.
	c.Inner.ZeroChecksum = false
	found := false
	for i := 0; i < 65536; i++ {
		c.Inner.SrcPort = uint16(i)
		p := build(t, c)
		if be.Uint16(p[40:42]) == 0xffff {
			assertChecksums(t, p)
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no mangled-zero sample found")
	}
}

func TestVXLANMTUBoundaryAndNoInnerPadding(t *testing.T) {
	c := base()
	c.Encap = "vxlan"
	c.VNI = 0xffffff
	c.Outer = c.Inner
	c.Outer.VLAN = 4094
	c.Inner.VLAN = 0
	// Outer IP 20+UDP 8+VXLAN 8+inner Ethernet 18+inner IP 44 = 98.
	p := build(t, c)
	if len(p) != 18+98 || be.Uint16(p[20:22]) != 98 {
		t.Fatal("unexpected tunneled length", len(p))
	}
	c.Payload = make([]byte, 1400)
	p = build(t, c)
	if be.Uint16(p[20:22]) != 1498 {
		t.Fatal("wrong outer length")
	}
	c.MTU = 1498
	build(t, c)
	c.MTU = 1497
	if _, e := Build(c, sequence.At(c, 0)); e == nil {
		t.Fatal("VXLAN MTU ignored")
	}
	c.MTU = 1500
	c.Payload = make([]byte, 1401)
	if _, e := Build(c, sequence.At(c, 0)); e == nil {
		t.Fatal("protocol pad not counted")
	}
}
func TestMaximumFieldsAndWriteLength(t *testing.T) {
	c := base()
	c.Template = "write-only"
	c.RemoteAddr = ^uint64(0)
	c.RKey = ^uint32(0)
	c.DQPN = 0xffffff
	c.PSN = 0xffffff
	c.Inner.SrcPort = 65535
	c.Inner.DstPort = 65535
	c.Payload = []byte{1, 2, 3}
	p := build(t, c)
	bth := p[42:]
	if be.Uint32(bth[4:8]) != 0xffffff || be.Uint32(bth[8:12]) != 0x80ffffff || be.Uint64(bth[12:20]) != ^uint64(0) || be.Uint32(bth[20:24]) != ^uint32(0) || be.Uint32(bth[24:28]) != 3 || bth[1] != 0x10 {
		t.Fatalf("%x", bth)
	}
	assertChecksums(t, p)
}

func TestJumboWireLengthsAndChecksums(t *testing.T) {
	c := base()
	c.MTU = 65535
	// RoCE padding gives a largest representable direct IPv4 size of 65532.
	c.Payload = bytes.Repeat([]byte{0xff}, 65488)
	p := build(t, c)
	if len(p) != 65546 || be.Uint16(p[16:18]) != 65532 || be.Uint16(p[38:40]) != 65512 {
		t.Fatal("jumbo lengths", len(p))
	}
	assertChecksums(t, p)
	// Caller-owned payload must remain unchanged after header masking/checksums.
	if !bytes.Equal(c.Payload, bytes.Repeat([]byte{0xff}, 65488)) {
		t.Fatal("builder mutated payload")
	}
	c.Encap = "vxlan"
	c.VNI = 1
	c.Outer = c.Inner
	c.Payload = c.Payload[:65436]
	p = build(t, c)
	if be.Uint16(p[16:18]) != 65530 {
		t.Fatal("jumbo VXLAN length")
	}
	assertChecksums(t, p)
	assertChecksums(t, p[50:]) // Ethernet/IP/UDP/VXLAN = 50 bytes.
}
