// Package packet constructs complete Ethernet frames without I/O.
package packet

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"roce-cli/internal/config"
	"roce-cli/internal/sequence"
)

var be = binary.BigEndian

func Build(c config.Config, f sequence.Fields) ([]byte, error) {
	if err := c.ValidatePacket(); err != nil {
		return nil, err
	}
	if f.PSN > 0xffffff {
		return nil, fmt.Errorf("PSN must fit in 24 bits")
	}
	pad := (4 - len(c.Payload)%4) % 4
	extra := 0
	if c.Template != "send-only" {
		extra = 16
	}
	// Reject oversized packets before allocating buffers or calculating checksums.
	outerIPLen := 20 + 8 + 12 + extra + len(c.Payload) + pad + 4
	if c.Encap == "vxlan" {
		outerIPLen += 20 + 8 + 8 + 14
		if c.Inner.VLAN >= 0 {
			outerIPLen += 4
		}
	}
	if outerIPLen > c.MTU {
		return nil, fmt.Errorf("outer IPv4 length %d exceeds mtu %d", outerIPLen, c.MTU)
	}
	body := make([]byte, 12+extra+len(c.Payload)+pad+4)
	body[0] = 4
	body[1] = byte(pad << 4)
	be.PutUint16(body[2:4], c.PKey)
	be.PutUint32(body[4:8], c.DQPN)
	be.PutUint32(body[8:12], f.PSN)
	if c.AckRequest {
		body[8] |= 0x80
	}
	switch c.Template {
	case "write-only":
		body[0] = 0x0a
		be.PutUint64(body[12:20], c.RemoteAddr)
		be.PutUint32(body[20:24], c.RKey)
		be.PutUint32(body[24:28], uint32(len(c.Payload)))
	case "cnp":
		body[0] = 0x81
		body[4] = 0x40
		clear(body[8:12])
	}
	copy(body[12+extra:], c.Payload)
	inner := c.Inner
	inner.SrcPort = f.SrcPort
	ip, err := ipUDP(inner, body, true, c.BadICRC)
	if err != nil {
		return nil, err
	}
	frame := ethernet(inner, ip)
	if c.Encap == "vxlan" {
		vx := make([]byte, 8+len(frame))
		vx[0] = 8
		be.PutUint32(vx[4:8], c.VNI<<8)
		copy(vx[8:], frame)
		ip, err = ipUDP(c.Outer, vx, false, false)
		if err != nil {
			return nil, err
		}
		frame = ethernet(c.Outer, ip)
	}
	if len(frame) < 60 {
		frame = append(frame, make([]byte, 60-len(frame))...)
	}
	return frame, nil
}

func ethernet(l config.Layer, ip []byte) []byte {
	h := 14
	if l.VLAN >= 0 {
		h += 4
	}
	p := make([]byte, h+len(ip))
	copy(p, l.DstMAC)
	copy(p[6:], l.SrcMAC)
	if h == 18 {
		be.PutUint16(p[12:], 0x8100)
		be.PutUint16(p[14:], uint16(l.PCP)<<13|uint16(l.VLAN))
	}
	be.PutUint16(p[h-2:], 0x0800)
	copy(p[h:], ip)
	return p
}

func ipUDP(l config.Layer, payload []byte, roce, bad bool) ([]byte, error) {
	if len(payload) > 65535-28 {
		return nil, fmt.Errorf("IPv4 length exceeds 65535")
	}
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	p[1] = l.DSCP<<2 | l.ECN
	be.PutUint16(p[2:4], uint16(len(p)))
	be.PutUint16(p[6:8], 0x4000)
	p[8] = l.TTL
	p[9] = 17
	src, dst := l.SrcIP.As4(), l.DstIP.As4()
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	be.PutUint16(p[20:22], l.SrcPort)
	be.PutUint16(p[22:24], l.DstPort)
	be.PutUint16(p[24:26], uint16(len(p)-20))
	copy(p[28:], payload)
	if roce {
		crc := icrc(p)
		if bad {
			crc ^= 1
		}
		binary.LittleEndian.PutUint32(p[len(p)-4:], crc)
	}
	be.PutUint16(p[10:12], checksum(p[:20]))
	if !l.ZeroChecksum {
		var pseudo [12]byte
		copy(pseudo[:], p[12:20])
		pseudo[9] = 17
		copy(pseudo[10:12], p[24:26])
		// The pseudo header is even-sized, so UDP can be summed independently.
		sum := finishChecksum(sumWords(pseudo[:]) + sumWords(p[20:]))
		if sum == 0 {
			sum = 0xffff
		}
		be.PutUint16(p[26:28], sum)
	}
	return p, nil
}

// icrc masks a fixed-size copy of the pseudo-LRH/IP/UDP/BTH headers, then
// streams the remaining RETH/data/pad into the CRC without copying the payload.
func icrc(ip []byte) uint32 {
	var p [8 + 20 + 8 + 12]byte
	for i := 0; i < 8; i++ {
		p[i] = 0xff
	}
	copy(p[8:], ip[:40])
	for _, i := range []int{1, 8, 10, 11, 26, 27, 32} {
		p[8+i] = 0xff
	}
	return crc32.Update(crc32.ChecksumIEEE(p[:]), crc32.IEEETable, ip[40:len(ip)-4])
}
func checksum(p []byte) uint16 {
	return finishChecksum(sumWords(p))
}

func sumWords(p []byte) uint32 {
	var sum uint32
	for len(p) >= 2 {
		sum += uint32(be.Uint16(p))
		p = p[2:]
	}
	if len(p) > 0 {
		sum += uint32(p[0]) << 8
	}
	return sum
}

func finishChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
