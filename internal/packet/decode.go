package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

var ErrUnrelated = errors.New("not a selected RoCE packet")
var ErrUnsupported = errors.New("unsupported packet format")

type DecodeOptions struct{ Port, VXLANPort uint16 }

type LayerReport struct {
	SrcMAC       string `json:"src_mac"`
	DstMAC       string `json:"dst_mac"`
	SrcIP        string `json:"src_ip"`
	DstIP        string `json:"dst_ip"`
	SrcPort      uint16 `json:"src_port"`
	DstPort      uint16 `json:"dst_port"`
	DSCP         uint8  `json:"dscp"`
	ECN          uint8  `json:"ecn"`
	TTL          uint8  `json:"ttl"`
	VLAN         int    `json:"vlan"` // -1 means absent.
	PCP          uint8  `json:"pcp"`
	IPLength     int    `json:"ip_length"`
	IPv4Checksum string `json:"ipv4_checksum"`
	UDPChecksum  string `json:"udp_checksum"`
}

type Report struct {
	Template      string       `json:"template"`
	Encap         string       `json:"encap"`
	Inner         LayerReport  `json:"inner"`
	Outer         *LayerReport `json:"outer,omitempty"`
	VNI           uint32       `json:"vni,omitempty"`
	DQPN          uint32       `json:"dqpn"`
	PSN           uint32       `json:"psn"`
	PKey          uint16       `json:"pkey"`
	AckRequest    bool         `json:"ack_request"`
	PayloadLength int          `json:"payload_length"`
	PadCount      int          `json:"pad_count"`
	RemoteAddr    *uint64      `json:"remote_addr,omitempty"`
	RKey          *uint32      `json:"rkey,omitempty"`
	ICRC          string       `json:"icrc"`
	Valid         bool         `json:"valid"`
	Issues        []string     `json:"issues,omitempty"`
}

// Decode never assumes a full frame: validate every enclosing length before
// accessing the next header. Ethernet padding is excluded using IPv4 length.
func Decode(frame []byte, o DecodeOptions) (Report, error) {
	r := Report{Encap: "none"}
	layer, ip, err := decodeLayer(frame, o.Port, o.VXLANPort)
	if err != nil {
		return r, err
	}
	if layer.DstPort == o.VXLANPort {
		r.Encap = "vxlan"
		outer := layer
		r.Outer = &outer
		vx := ip[28:]
		if len(vx) < 8 {
			return r, fmt.Errorf("truncated VXLAN header")
		}
		if vx[0] != 8 || vx[1] != 0 || vx[2] != 0 || vx[3] != 0 || vx[7] != 0 {
			return r, fmt.Errorf("%w: VXLAN flags/reserved fields", ErrUnsupported)
		}
		r.VNI = be.Uint32(vx[4:8]) >> 8
		layer, ip, err = decodeLayer(vx[8:], o.Port)
		if err != nil {
			return r, err
		}
	}
	if layer.DstPort != o.Port {
		return r, ErrUnrelated
	}
	r.Inner = layer
	b := ip[28:]
	if len(b) < 16 {
		return r, fmt.Errorf("truncated BTH/ICRC")
	}
	switch b[0] {
	case 4:
		r.Template = "send-only"
	case 10:
		r.Template = "write-only"
	case 129:
		r.Template = "cnp"
	default:
		return r, fmt.Errorf("%w: opcode 0x%02x", ErrUnsupported, b[0])
	}
	r.PadCount = int(b[1] >> 4 & 3)
	r.PKey = be.Uint16(b[2:4])
	r.DQPN = be.Uint32(b[4:8]) & 0xffffff
	r.PSN = be.Uint32(b[8:12]) & 0xffffff
	r.AckRequest = b[8]&0x80 != 0
	header := 12
	if r.Template != "send-only" {
		header += 16
	}
	end := len(b) - 4 - r.PadCount
	if end < header {
		return r, fmt.Errorf("truncated %s header/padding", r.Template)
	}
	r.PayloadLength = end - header
	issue := func(s string) { r.Issues = append(r.Issues, s) }
	if len(b)%4 != 0 {
		issue("RoCE length is not a multiple of 4")
	}
	if b[1]&15 != 0 || b[4]&0x3f != 0 || b[8]&0x7f != 0 {
		issue("BTH version/reserved bits are nonzero")
	}
	if r.Template == "write-only" {
		addr, key := be.Uint64(b[12:20]), be.Uint32(b[20:24])
		r.RemoteAddr = &addr
		r.RKey = &key
		if be.Uint32(b[24:28]) != uint32(r.PayloadLength) {
			issue("RETH length does not match payload")
		}
	}
	if r.Template == "cnp" {
		if len(b) != 32 || b[4]&0x40 == 0 || r.PSN != 0 || r.AckRequest || r.PadCount != 0 {
			issue("invalid CNP fields/length")
		}
		for _, v := range b[12:28] {
			if v != 0 {
				issue("nonzero CNP reserved area")
				break
			}
		}
	}
	r.ICRC = "valid"
	if binary.LittleEndian.Uint32(b[len(b)-4:]) != icrc(ip) {
		r.ICRC = "invalid"
		issue("invalid ICRC")
	}
	checkLayer := func(name string, l LayerReport) {
		if l.IPv4Checksum == "invalid" {
			issue(name + " IPv4 checksum invalid")
		}
		if l.UDPChecksum == "invalid" {
			issue(name + " UDP checksum invalid")
		}
	}
	checkLayer("RoCE", r.Inner)
	if r.Outer != nil {
		checkLayer("outer", *r.Outer)
	}
	r.Valid = len(r.Issues) == 0
	return r, nil
}

func decodeLayer(frame []byte, ports ...uint16) (LayerReport, []byte, error) {
	l := LayerReport{VLAN: -1}
	if len(frame) < 14 {
		return l, nil, fmt.Errorf("truncated Ethernet header")
	}
	l.DstMAC = net.HardwareAddr(frame[:6]).String()
	l.SrcMAC = net.HardwareAddr(frame[6:12]).String()
	offset := 14
	typ := be.Uint16(frame[12:14])
	if typ == 0x8100 {
		if len(frame) < 18 {
			return l, nil, fmt.Errorf("truncated VLAN header")
		}
		tci := be.Uint16(frame[14:16])
		l.VLAN = int(tci & 0xfff)
		l.PCP = uint8(tci >> 13)
		typ = be.Uint16(frame[16:18])
		offset = 18
	}
	if typ == 0x8100 || typ == 0x88a8 {
		return l, nil, fmt.Errorf("%w: stacked/provider VLAN", ErrUnsupported)
	}
	if typ != 0x0800 {
		return l, nil, ErrUnrelated
	}
	p := frame[offset:]
	if len(p) < 20 {
		return l, nil, fmt.Errorf("truncated IPv4 header")
	}
	if p[0]>>4 != 4 {
		return l, nil, fmt.Errorf("invalid IPv4 version")
	}
	if p[9] != 17 {
		return l, nil, ErrUnrelated
	}
	// Classify readable UDP ports before enforcing the supported RoCE layout.
	// In particular, unrelated UDP with IPv4 options must not fail --strict.
	ihl := int(p[0]&15) * 4
	total := int(be.Uint16(p[2:4]))
	if ihl >= 20 && total >= ihl+4 && len(p) >= ihl+4 && be.Uint16(p[6:8])&0x1fff == 0 {
		dst := be.Uint16(p[ihl+2 : ihl+4])
		selected := false
		for _, port := range ports {
			if dst == port {
				selected = true
				break
			}
		}
		if !selected {
			return l, nil, ErrUnrelated
		}
	}
	if p[0]&15 != 5 {
		return l, nil, fmt.Errorf("%w: IPv4 options", ErrUnsupported)
	}
	if be.Uint16(p[6:8])&0x3fff != 0 {
		return l, nil, fmt.Errorf("%w: IPv4 fragmentation", ErrUnsupported)
	}
	if total < 28 || total > len(p) {
		return l, nil, fmt.Errorf("invalid/truncated IPv4 length %d", total)
	}
	p = p[:total]
	if int(be.Uint16(p[24:26])) != total-20 {
		return l, nil, fmt.Errorf("UDP length differs from IPv4 payload")
	}
	l.SrcIP = netip.AddrFrom4([4]byte(p[12:16])).String()
	l.DstIP = netip.AddrFrom4([4]byte(p[16:20])).String()
	l.SrcPort = be.Uint16(p[20:22])
	l.DstPort = be.Uint16(p[22:24])
	l.DSCP = p[1] >> 2
	l.ECN = p[1] & 3
	l.TTL = p[8]
	l.IPLength = total
	l.IPv4Checksum = "valid"
	if checksum(p[:20]) != 0 {
		l.IPv4Checksum = "invalid"
	}
	l.UDPChecksum = "disabled"
	if be.Uint16(p[26:28]) != 0 {
		pseudo := [12]byte{}
		copy(pseudo[:8], p[12:20])
		pseudo[9] = 17
		copy(pseudo[10:], p[24:26])
		l.UDPChecksum = "valid"
		if finishChecksum(sumWords(pseudo[:])+sumWords(p[20:])) != 0 {
			l.UDPChecksum = "invalid"
		}
	}
	return l, p, nil
}
