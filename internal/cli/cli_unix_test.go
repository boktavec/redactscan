//go:build darwin || linux

package cli

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRedactFIFOIsRefusedWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan result, 1)
	go func() { done <- run([]string{"redact", fifo}, strings.NewReader("")) }()
	select {
	case got := <-done:
		assertFailure(t, got, 3, `redactscan: cannot open "`+fifo+`": not a regular file (fifo)`+"\n")
	case <-time.After(2 * time.Second):
		t.Fatal("redact blocked on a FIFO")
	}
}
