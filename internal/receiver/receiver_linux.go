//go:build linux

package receiver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"roce-cli/internal/pcap"
)

type socket struct {
	fd              int
	index           int
	buffer, control []byte
}

// Linux UAPI linux/if_packet.h; absent from Go's frozen syscall API on amd64.
const packetAuxdata = 8

func Open(name string) (Receiver, error) {
	iface, e := net.InterfaceByName(name)
	if e != nil {
		return nil, e
	}
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("receive requires an up Ethernet interface")
	}
	protocol := int(binary.NativeEndian.Uint16([]byte{0, 3}))
	// Protocol zero prevents packets from other interfaces being queued before bind.
	fd, e := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, 0)
	if e != nil {
		return nil, fmt.Errorf("open capture socket (requires root or CAP_NET_RAW): %w", e)
	}
	fail := func(err error) (Receiver, error) { syscall.Close(fd); return nil, err }
	if e = syscall.SetsockoptInt(fd, syscall.SOL_PACKET, packetAuxdata, 1); e != nil {
		return fail(e)
	}
	if e = syscall.Bind(fd, &syscall.SockaddrLinklayer{Ifindex: iface.Index, Protocol: uint16(protocol)}); e != nil {
		return fail(e)
	}
	return &socket{fd: fd, index: iface.Index, buffer: make([]byte, pcap.SnapLen), control: make([]byte, syscall.CmsgSpace(20))}, nil
}
func (s *socket) Close() error { return syscall.Close(s.fd) }
func (s *socket) Receive(ctx context.Context) (Frame, error) {
	for {
		if e := ctx.Err(); e != nil {
			return Frame{}, e
		}
		n, oobn, flags, from, e := syscall.Recvmsg(s.fd, s.buffer, s.control, syscall.MSG_DONTWAIT)
		if errors.Is(e, syscall.EINTR) {
			continue
		}
		if errors.Is(e, syscall.EAGAIN) {
			timer := time.NewTimer(time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return Frame{}, ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if e != nil {
			return Frame{}, e
		}
		addr, ok := from.(*syscall.SockaddrLinklayer)
		if !ok || addr.Ifindex != s.index || addr.Pkttype == syscall.PACKET_OUTGOING || addr.Pkttype == syscall.PACKET_OTHERHOST {
			continue
		}
		if flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
			return Frame{}, fmt.Errorf("capture truncated by socket buffer")
		}
		captured := Frame{Bytes: append([]byte(nil), s.buffer[:n]...), Timestamp: time.Now()}
		controls, e := syscall.ParseSocketControlMessage(s.control[:oobn])
		if e != nil {
			return Frame{}, e
		}
		for _, c := range controls {
			if c.Header.Level == syscall.SOL_PACKET && c.Header.Type == packetAuxdata {
				captured.Bytes, e = RestoreVLAN(captured.Bytes, c.Data)
				if e != nil {
					return Frame{}, e
				}
			}
		}
		return captured, nil
	}
}
