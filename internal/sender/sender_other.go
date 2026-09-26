//go:build !linux

package sender

import (
	"fmt"
	"net"
)

func Open(net.Interface) (Sender, error) {
	return nil, fmt.Errorf("send is supported only on Linux; use build for offline output")
}
