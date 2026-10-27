//go:build darwin || linux

package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/safefs"
)

// marker is put in names and link targets; it must never reach an error.
const marker = "MARKER-ingest-7c1e"

// tempRoot returns a symlink-free temp directory (macOS TMPDIR goes through
// /var, a symlink to /private/var, which OpenDirRoot refuses).
func tempRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func fdCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// walk runs Walk with a 2 s timeout, checks that every output validates, that
// no descriptor leaks, and that no error contains the marker.
func walk(t *testing.T, root string, lim Limits) (Result, error) {
	t.Helper()
	before := fdCount(t)
	var res Result
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		res, err = Walk(root, lim)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Walk blocked")
	}
	if after := fdCount(t); after != before {
		t.Errorf("descriptors: %d before, %d after", before, after)
	}
	for _, a := range res.Artifacts {
		if e := a.Validate(); e != nil {
			t.Errorf("artifact %s invalid: %v", a.ID, e)
		}
		// Files under / and /dev are not ours to open (e.g. unreadable ones
		// are still regular files, but /proc-like entries may refuse).
		if root == "/" || root == "/dev" {
			continue
		}
		if f, e := safefs.OpenRegular(a.Path); e != nil {
			t.Errorf("artifact %s: OpenRegular: %v", a.ID, e)
		} else {
			_ = f.Close()
		}
	}
	for _, f := range res.Findings {
		if e := f.Validate(); e != nil {
			t.Errorf("finding %s invalid: %v", f.ID, e)
		}
	}
	if err != nil && strings.Contains(err.Error(), marker) {
		t.Errorf("error leaks marker: %v", err)
	}
	return res, err
}

func mkfile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mkfifo(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mksymlink(t *testing.T, target, path string) {
	t.Helper()
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

// swapHook replaces beforeChildOpen for one test.
func swapHook(t *testing.T, hook func(name string)) {
	t.Helper()
	old := beforeChildOpen
	beforeChildOpen = hook
	t.Cleanup(func() { beforeChildOpen = old })
}

func swapReadNames(t *testing.T, fn func(*os.File, int) ([]string, error)) {
	t.Helper()
	old := readNames
	readNames = fn
	t.Cleanup(func() { readNames = old })
}

func findingsOf(res Result, id string) []finding.Finding {
	var out []finding.Finding
	for _, f := range res.Findings {
		if strings.HasPrefix(f.ID, id+"-") {
			out = append(out, f)
		}
	}
	return out
}

func relPaths(res Result) []string {
	var out []string
	for _, a := range res.Artifacts {
		out = append(out, a.RelativePath)
	}
	return out
}

// maxPath is the longest Path Walk accepts.
const maxPath = MaxPathBytes - len(systemLinkHeadroom) - 1

// pathOfLen builds a file (or an empty directory) whose Path is exactly total
// bytes when the typed prefix is prefixLen bytes long (including the trailing
// slash), creating it under the real directory base. It uses a Root per level
// because a single path that long may exceed PATH_MAX.
func pathOfLen(t *testing.T, base string, prefixLen, total int, leafDir bool) {
	t.Helper()
	remaining := total - prefixLen
	r, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	for remaining > 255 {
		dir := strings.Repeat("d", 100)
		if err := r.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		next, err := r.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Close()
		r = next
		remaining -= len(dir) + 1
	}
	leaf := strings.Repeat("f", remaining)
	if leafDir {
		err = r.Mkdir(leaf, 0o700)
	} else {
		var f *os.File
		if f, err = r.Create(leaf); err == nil {
			_ = f.Close()
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
}
