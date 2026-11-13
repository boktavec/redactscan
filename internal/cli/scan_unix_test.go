//go:build darwin || linux

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/boktavec/redactscan/internal/finding"
)

func TestScanRefusesUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(dir, "linkdir")
	if err := os.Symlink(dir, linkDir); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, path, reason string
	}{
		{"final symlink", link, "symlink refused"},
		{"symlinked parent", filepath.Join(linkDir, "target.txt"), "symlink refused"},
		{"directory", dir, "not a regular file (directory)"},
		{"fifo", fifo, "not a regular file (fifo)"},
		{"device", os.DevNull, "not a regular file (device)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			done := make(chan result, 1)
			go func() { done <- run([]string{"scan", tt.path}, strings.NewReader("")) }()
			select {
			case got := <-done:
				assertFailure(t, got, exitIO, `redactscan: cannot open "`+tt.path+`": `+tt.reason+"\n")
			case <-time.After(2 * time.Second):
				t.Fatal("scan blocked")
			}
		})
	}
}

func TestScanHostileFileNameIsEscaped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a\x1b[31m\u202eb.log")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Skipf("file system rejects the name: %v", err)
	}
	useScanners(t, fakeScanner{name: "a", fileIsPath: true,
		findings: []finding.Finding{finding1("f", finding.SeverityLow, "", 1, "T")}})
	// The temp dir itself is plain ASCII, so only the base name is hostile.
	for _, tt := range []struct{ flag, want string }{
		{"", `a\x1b[31m\u202eb.log:1`},
		{"-json", `a\u001b[31m\u202eb.log`},
	} {
		args := []string{"scan", path}
		if tt.flag != "" {
			args = []string{"scan", tt.flag, path}
		}
		got := run(args, strings.NewReader(""))
		if got.code != 0 || got.stderr != "" || !strings.Contains(got.stdout, tt.want) {
			t.Errorf("%q: want %q in %+v", tt.flag, tt.want, got)
		}
		assertNoDangerousRune(t, got.stdout)
	}
}
