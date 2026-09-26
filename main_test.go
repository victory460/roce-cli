//go:build linux || darwin

package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Exercise inherited stdout and the real process signal handler, rather than
// only a context-cancelled writer inside the app package.
func TestBlockedStdoutSignal(t *testing.T) {
	for _, signal := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(signal.String(), func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			var stderr bytes.Buffer
			cmd := exec.Command(os.Args[0], "-test.run=^TestSignalHelper$")
			cmd.Env = append(os.Environ(), "ROCE_CLI_SIGNAL_HELPER=1")
			cmd.Stdout = w
			cmd.Stderr = &stderr
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer cmd.Process.Kill()
			w.Close()
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			if err = r.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err = io.ReadFull(r, make([]byte, 1)); err != nil {
				cmd.Process.Kill()
				<-done
				t.Fatal(err)
			}
			time.Sleep(30 * time.Millisecond)
			if err = cmd.Process.Signal(signal); err != nil {
				t.Fatal(err)
			}
			select {
			case err = <-done:
				if cmd.ProcessState.ExitCode() != 130 || !strings.Contains(stderr.String(), "status=interrupted") {
					t.Fatalf("exit=%v stderr=%s", err, stderr.String())
				}
			case <-time.After(3 * time.Second):
				cmd.Process.Kill()
				<-done
				t.Fatal("process ignored signal while stdout blocked")
			}
		})
	}
}

func TestSignalHelper(t *testing.T) {
	if os.Getenv("ROCE_CLI_SIGNAL_HELPER") != "1" {
		return
	}
	os.Args = strings.Fields("roce-cli build --src-mac 02:00:00:00:00:01 --dst-mac 02:00:00:00:00:02 --src-ip 192.0.2.1 --dst-ip 192.0.2.2 --dqpn 1 --pcap - --count 1000000")
	os.Exit(run())
}
