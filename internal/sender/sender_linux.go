//go:build linux

package sender

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

type socket struct{ fd, index int }

func Open(iface net.Interface) (Sender, error) {
	protocol := int(binary.NativeEndian.Uint16([]byte{0, 3})) // htons(ETH_P_ALL)
	fd, e := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, protocol)
	if e != nil {
		return nil, fmt.Errorf("open AF_PACKET (requires root or CAP_NET_RAW): %w", e)
	}
	if e = syscall.Bind(fd, &syscall.SockaddrLinklayer{Ifindex: iface.Index, Protocol: uint16(protocol)}); e != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind AF_PACKET: %w", e)
	}
	return &socket{fd, iface.Index}, nil
}
func (s *socket) Close() error { return syscall.Close(s.fd) }
func (s *socket) Send(ctx context.Context, p []byte) error {
	if len(p) < 14 {
		return fmt.Errorf("short Ethernet frame")
	}
	addr := &syscall.SockaddrLinklayer{Ifindex: s.index, Halen: 6, Protocol: binary.NativeEndian.Uint16(p[12:14])}
	copy(addr.Addr[:], p[:6])
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		e := syscall.Sendto(s.fd, p, syscall.MSG_DONTWAIT, addr)
		if e == nil {
			return nil
		}
		if errors.Is(e, syscall.EINTR) {
			continue
		}
		if !errors.Is(e, syscall.EAGAIN) && !errors.Is(e, syscall.ENOBUFS) {
			return fmt.Errorf("AF_PACKET send: %w", e)
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
