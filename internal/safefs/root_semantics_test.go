//go:build darwin || linux

package safefs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// These tests pin the os.Root behavior that directory ingestion relies on
// (docs/features/recursive-ingest/spec.md 3.6). They run on macOS and Linux;
// a failure on either OS means the design needs another look.

const openDirFlags = os.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NONBLOCK

// rootTree builds, under a symlink-free temp dir, a "root" directory holding
// the cases below plus an "outside" directory that must never be reached.
func rootTree(t *testing.T) (*os.Root, string) {
	t.Helper()
	base := tempDir(t)
	root := filepath.Join(base, "root")
	mustMkdir(t, root)
	mustMkdir(t, filepath.Join(base, "outside"))
	mustMkdir(t, filepath.Join(root, "sub"))
	writeFile(t, filepath.Join(root, "file"), []byte("x"))
	for name, target := range map[string]string{
		"in-root":        "file",
		"dangling":       "missing",
		"self":           "self",
		"loop-a":         "loop-b",
		"loop-b":         "loop-a",
		"escape-rel":     "../outside",
		"escape-abs":     filepath.Join(base, "outside"),
		"escape-missing": "../outside/missing",
	} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	// Linux refuses to create a symlink with an empty target (ENOENT); macOS
	// allows it. Tests that need it skip when it cannot be created.
	_ = os.Symlink("", filepath.Join(root, "empty"))
	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, root
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestRootStatSymlinkClassification(t *testing.T) {
	r, _ := rootTree(t)
	tests := []struct {
		name  string
		check func(error) bool
		want  string
	}{
		{"in-root", func(err error) bool { return err == nil }, "nil"},
		{"dangling", func(err error) bool { return errors.Is(err, fs.ErrNotExist) }, "fs.ErrNotExist"},
		{"self", func(err error) bool { return errors.Is(err, syscall.ELOOP) }, "ELOOP"},
		{"loop-a", func(err error) bool { return errors.Is(err, syscall.ELOOP) }, "ELOOP"},
		{"escape-rel", isRootEscape, "root escape"},
		{"escape-abs", isRootEscape, "root escape"},
		{"escape-missing", isRootEscape, "root escape"},
		{"empty", isRootEscape, "non-Errno path error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := r.Lstat(tt.name); err != nil {
				t.Skip("symlink cannot be created on this OS")
			}
			if _, err := r.Stat(tt.name); !tt.check(err) {
				t.Errorf("Stat(%q) error = %v, want %s", tt.name, err, tt.want)
			}
		})
	}
}

func TestRootEscapeIsNotAnErrno(t *testing.T) {
	r, _ := rootTree(t)
	_, err := r.Stat("escape-rel")
	var pe *fs.PathError
	if !errors.As(err, &pe) {
		t.Fatalf("error %v is not a *fs.PathError", err)
	}
	var errno syscall.Errno
	if errors.As(pe.Err, &errno) {
		t.Errorf("escape error wraps errno %v; spec 3.6 assumes a non-Errno", errno)
	}
	for _, name := range []string{"dangling", "self", "in-root"} {
		if _, err := r.Stat(name); isRootEscape(err) {
			t.Errorf("Stat(%q) misclassified as an escape: %v", name, err)
		}
	}
}

func TestIsRootEscapeExcludesClosedAndInvalid(t *testing.T) {
	r, _ := rootTree(t)
	_ = r.Close()
	_, err := r.Stat("file")
	if err == nil || isRootEscape(err) {
		t.Errorf("Stat on a closed root: error = %v, want a non-escape failure", err)
	}
	for _, inner := range []error{fs.ErrClosed, fs.ErrInvalid, syscall.ENOENT} {
		if isRootEscape(&fs.PathError{Op: "x", Path: "p", Err: inner}) {
			t.Errorf("isRootEscape treats %v as an escape", inner)
		}
	}
}

func TestRootOpenDirectoryRefusesFIFOWithoutBlocking(t *testing.T) {
	r, root := rootTree(t)
	if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("fifo", filepath.Join(root, "fifo-link")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fifo", "fifo-link"} {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() {
				f, err := r.OpenFile(name, openDirFlags, 0)
				if f != nil {
					_ = f.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, syscall.ENOTDIR) {
					t.Errorf("OpenFile error = %v, want ENOTDIR", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("OpenFile blocked on a FIFO")
			}
		})
	}
}

func TestRootOpenDirectoryFollowsInRootSymlink(t *testing.T) {
	r, root := rootTree(t)
	if err := os.Symlink("sub", filepath.Join(root, "sub-link")); err != nil {
		t.Fatal(err)
	}
	f, err := r.OpenFile("sub-link", openDirFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	lst, err := r.Lstat("sub-link")
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(st, lst) {
		t.Error("descriptor matches the symlink's Lstat; OpenChildDir's SameFile check would not detect the swap")
	}
}

func TestRootOpenDirectoryEscapeIsRefused(t *testing.T) {
	r, _ := rootTree(t)
	for _, name := range []string{"escape-rel", "escape-abs"} {
		f, err := r.OpenFile(name, openDirFlags, 0)
		if err == nil {
			_ = f.Close()
			t.Fatalf("OpenFile(%q) escaped the root", name)
		}
		if !isRootEscape(err) {
			t.Errorf("OpenFile(%q) error = %v, want root escape", name, err)
		}
	}
}

func TestReaddirnamesBatchesOnRootOpenedDirectory(t *testing.T) {
	r, root := rootTree(t)
	const files = 30
	for i := range files {
		writeFile(t, filepath.Join(root, "sub", fmt.Sprintf("f%02d", i)), nil)
	}
	f, err := r.OpenFile("sub", openDirFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var total int
	for {
		names, err := f.Readdirnames(8)
		total += len(names)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if total != files {
		t.Errorf("listed %d names, want %d", total, files)
	}
}

func TestOpenRootThroughDescriptorPath(t *testing.T) {
	f, err := os.Open(tempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	r, err := rootFromDir(f)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if !sameAsRoot(f, r) {
		t.Error("root is not the directory behind the descriptor")
	}
}
