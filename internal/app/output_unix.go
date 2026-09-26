//go:build linux || darwin

package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
)

// Inherited stdout pipes are blocking os.Files and do not support deadlines.
// Give pipes an independently owned descriptor registered with Go's poller.
// O_NONBLOCK is shared by dup descriptors: restore its original state on exit.
func prepareOutput(ctx context.Context, w io.Writer) (io.Writer, func() error, error) {
	f, ok := w.(*os.File)
	if !ok {
		wrapped, stop := cancelOutput(ctx, w)
		return wrapped, func() error { stop(); return nil }, nil
	}
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		wrapped, stop := cancelOutput(ctx, w)
		return wrapped, func() error { stop(); return nil }, nil
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	fd := -1
	var flags uintptr
	var opErr error
	err = raw.Control(func(original uintptr) {
		var errno syscall.Errno
		flags, _, errno = syscall.Syscall(syscall.SYS_FCNTL, original, syscall.F_GETFL, 0)
		if errno != 0 {
			opErr = errno
			return
		}
		fd, opErr = syscall.Dup(int(original))
	})
	if err != nil {
		return nil, nil, err
	}
	if opErr != nil {
		return nil, nil, opErr
	}
	syscall.CloseOnExec(fd)
	if err = syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, nil, err
	}
	pipe := os.NewFile(uintptr(fd), f.Name())
	restore := func() error {
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFL, flags)
		var restoreErr error
		if errno != 0 {
			restoreErr = fmt.Errorf("restore pipe flags: %w", errno)
		}
		return errors.Join(restoreErr, pipe.Close())
	}
	// Fail explicitly if this platform cannot make the pipe cancellable.
	if err = pipe.SetWriteDeadline(time.Time{}); err != nil {
		return nil, nil, errors.Join(err, restore())
	}
	wrapped, stop := cancelOutput(ctx, pipe)
	return wrapped, func() error { stop(); return restore() }, nil
}
