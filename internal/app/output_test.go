//go:build linux || darwin

package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestBlockedPipeCancellation(t *testing.T) {
	for _, mode := range []string{"pcap", "hex"} {
		t.Run(mode, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			// Fd deliberately makes this look like inherited, blocking stdout.
			_ = w.Fd()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var summary bytes.Buffer
			done := make(chan int, 1)
			args := buildArgs("--count", "1000000")
			if mode == "pcap" {
				args = append(args, "--pcap", "-")
			} else {
				args = append(args, "--hex")
			}
			go func() { done <- Run(ctx, args, w, &summary, Dependencies{}) }()
			// Wait for output before letting the pipe fill with its reader idle.
			first := make([]byte, 1)
			if _, err = io.ReadFull(r, first); err != nil {
				t.Fatal(err)
			}
			time.Sleep(30 * time.Millisecond)
			cancel()
			select {
			case code := <-done:
				if code != 130 {
					t.Fatalf("code=%d summary=%s", code, summary.String())
				}
			case <-time.After(2 * time.Second):
				r.Close() // Unblock broken implementations so the test doesn't leak a worker.
				<-done
				t.Fatal("blocked pipe ignored cancellation")
			}
			w.Close()
			rest, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			output := append(first, rest...)
			var complete int
			if mode == "pcap" {
				for offset := 24; offset+16 <= len(output); {
					n := int(binary.LittleEndian.Uint32(output[offset+8:]))
					offset += 16 + n
					if offset > len(output) {
						break
					}
					complete++
				}
			} else {
				complete = bytes.Count(output, []byte{'\n'})
			}
			var reported int
			if _, err = fmt.Sscanf(summary.String()[strings.Index(summary.String(), "generated "):], "generated frames=%d", &reported); err != nil {
				t.Fatal(err, summary.String())
			}
			if complete == 0 || reported != complete {
				t.Fatalf("complete=%d reported=%d", complete, reported)
			}
		})
	}
}
