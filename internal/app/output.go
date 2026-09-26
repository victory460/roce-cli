package app

import (
	"context"
	"io"
	"time"
)

type contextWriter struct {
	ctx context.Context
	w   io.Writer
}

func (w contextWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := w.w.Write(p)
	if err != nil && w.ctx.Err() != nil {
		err = w.ctx.Err()
	}
	return n, err
}

// cancelOutput interrupts pollable writes without leaving a blocked worker
// goroutine behind. The caller must stop the callback before closing the file.
func cancelOutput(ctx context.Context, w io.Writer) (io.Writer, func()) {
	deadline, ok := w.(interface{ SetWriteDeadline(time.Time) error })
	if !ok || deadline.SetWriteDeadline(time.Time{}) != nil {
		return contextWriter{ctx, w}, func() {}
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = deadline.SetWriteDeadline(time.Now())
		close(done)
	})
	return contextWriter{ctx, w}, func() {
		if !stop() {
			<-done
		}
		_ = deadline.SetWriteDeadline(time.Time{})
	}
}
