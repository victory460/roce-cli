//go:build !linux && !darwin

package app

import (
	"context"
	"io"
)

func prepareOutput(ctx context.Context, w io.Writer) (io.Writer, func() error, error) {
	wrapped, stop := cancelOutput(ctx, w)
	return wrapped, func() error { stop(); return nil }, nil
}
