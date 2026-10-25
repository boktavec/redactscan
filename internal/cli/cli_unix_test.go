//go:build darwin || linux

package cli

import (
	"os"
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

func TestOutputModeIgnoresUmask(t *testing.T) { // not parallel: Umask is process-wide
	for _, umask := range []int{0o000, 0o077, 0o277} {
		for _, force := range []bool{false, true} {
			// Fixtures are created before the umask changes: 0o277 would make
			// the directory unwritable.
			dir := t.TempDir()
			in := writeIn(t, dir, "app.log", awsKey(29))
			args := []string{"redact", in}
			if force {
				writeIn(t, dir, "app_cleaned.log", "old")
				args = []string{"redact", "-force", in}
			}

			old := syscall.Umask(umask)
			got := run(args, strings.NewReader(""))
			syscall.Umask(old)

			fi, err := os.Stat(filepath.Join(dir, "app_cleaned.log"))
			if got.code != 0 || err != nil {
				t.Fatalf("umask %03o force %v: got %+v, %v", umask, force, got, err)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("umask %03o force %v: mode = %v", umask, force, fi.Mode().Perm())
			}
			if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
				t.Errorf("umask %03o force %v: owner is not the current user", umask, force)
			}
		}
	}
}
