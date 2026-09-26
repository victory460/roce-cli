// Package sender submits complete Ethernet frames to a Linux packet socket.
package sender

import "context"

type Sender interface {
	Send(context.Context, []byte) error
	Close() error
}
