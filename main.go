package main

import (
	"context"
	"os"
	"os/signal"
	"roce-cli/internal/app"
	"syscall"
)

var version = "dev"

func main() { os.Exit(run()) }
func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Restore default handling after the first signal so a second interrupt
	// can terminate even if an external device/filesystem cannot cancel I/O.
	go func() {
		<-ctx.Done()
		stop()
	}()
	app.Version = version
	return app.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, app.Dependencies{})
}
