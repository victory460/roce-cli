// Package receiver captures incoming raw Ethernet frames, not RDMA completions.
package receiver

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"
)

type Frame struct {
	Bytes     []byte
	Timestamp time.Time
}
type Receiver interface {
	Receive(context.Context) (Frame, error)
	Close() error
}

// RestoreVLAN consumes the Linux tpacket_auxdata structure in native byte order.
// TP_STATUS_VLAN_VALID must be used: VLAN 0/PCP 0 is still a real tag.
func RestoreVLAN(frame, aux []byte) ([]byte, error) {
	if len(aux) < 20 {
		return nil, fmt.Errorf("truncated PACKET_AUXDATA")
	}
	status := binary.NativeEndian.Uint32(aux)
	if status&(1<<4) == 0 {
		return frame, nil
	}
	if len(frame) < 14 {
		return nil, fmt.Errorf("truncated Ethernet frame with VLAN metadata")
	}
	tci := binary.NativeEndian.Uint16(aux[16:18])
	tpid := uint16(0x8100)
	if status&(1<<6) != 0 {
		tpid = binary.NativeEndian.Uint16(aux[18:20])
	}
	p := make([]byte, len(frame)+4)
	copy(p, frame[:12])
	binary.BigEndian.PutUint16(p[12:14], tpid)
	binary.BigEndian.PutUint16(p[14:16], tci)
	copy(p[16:], frame[12:])
	return p, nil
}
