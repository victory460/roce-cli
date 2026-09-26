//go:build !linux

package receiver

import "fmt"

func Open(string) (Receiver, error) {
	return nil, fmt.Errorf("receive is supported only on Linux; use inspect for offline PCAP validation")
}
