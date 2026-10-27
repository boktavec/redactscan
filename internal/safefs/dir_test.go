//go:build darwin || linux

package safefs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const dirMarker = "MARKER-dir-name-7d2a"

// withTimeout runs fn and fails the test if it does not return within 2 s.
func withTimeout(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("call blocked")
	}
}

func openDirRootTimed(t *testing.T, path string) (f *os.File, r *os.Root, err error) {
	t.Helper()
	withTimeout(t, func() { f, r, err = OpenDirRoot(path) })
	return f, r, err
}

func closeDirRoot(f *os.File, r *os.Root) {
	if f != nil {
		_ = f.Close()
	}
	if r != nil {
		_ = r.Close()
	}
}

func mustFIFO(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, path string) {
	t.Helper()
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func TestOpenDirRootOpensDirectory(t *testing.T) {
	dir := tempDir(t)
	writeFile(t, filepath.Join(dir, "a"), []byte("x"))

	f, r, err := openDirRootTimed(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDirRoot(f, r)

	names, err := f.Readdirnames(-1)
	if err != nil || len(names) != 1 || names[0] != "a" {
		t.Errorf("Readdirnames = %v, %v; want [a]", names, err)
	}
	if !sameAsRoot(f, r) {
		t.Error("root is not pinned to the returned directory")
	}
	if _, err := r.Lstat("a"); err != nil {
		t.Errorf("root.Lstat: %v", err)
	}
}

func TestOpenDirRootOpensFilesystemRoot(t *testing.T) {
	f, r, err := openDirRootTimed(t, "/")
	if err != nil {
		t.Fatal(err)
	}
	closeDirRoot(f, r)
}

func TestOpenDirRootOpensRelativePath(t *testing.T) {
	dir := tempDir(t)
	mustMkdir(t, filepath.Join(dir, "sub"))
	t.Chdir(dir)

	f, r, err := openDirRootTimed(t, "sub")
	if err != nil {
		t.Fatal(err)
	}
	closeDirRoot(f, r)
}

func TestOpenDirRootRefusals(t *testing.T) {
	dir := tempDir(t)
	mustMkdir(t, filepath.Join(dir, "real"))
	mustMkdir(t, filepath.Join(dir, "real", "sub"))
	writeFile(t, filepath.Join(dir, "file"), []byte("x"))
	mustFIFO(t, filepath.Join(dir, "fifo"))
	mustSymlink(t, "real", filepath.Join(dir, "link"))
	mustSymlink(t, "missing", filepath.Join(dir, "dangling"))

	tests := []struct {
		name string
		path string
		want error
	}{
		{"regular file", filepath.Join(dir, "file"), ErrNotDir},
		{"fifo", filepath.Join(dir, "fifo"), ErrNotDir},
		{"symlink root", filepath.Join(dir, "link"), ErrSymlink},
		{"dangling symlink root", filepath.Join(dir, "dangling"), ErrSymlink},
		{"symlinked parent", filepath.Join(dir, "link", "sub"), ErrSymlink},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, r, err := openDirRootTimed(t, tt.path)
			closeDirRoot(f, r)
			if !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
			if f != nil || r != nil {
				t.Error("returned a handle with an error")
			}
		})
	}

	t.Run("missing", func(t *testing.T) {
		_, _, err := OpenDirRoot(filepath.Join(dir, "missing"))
		if !errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrNotDir) || errors.Is(err, ErrSymlink) {
			t.Errorf("error = %v, want a plain not-exist opError", err)
		}
	})
}

func TestOpenDirRootErrorTextHasNoPathOrOSText(t *testing.T) {
	dir := tempDir(t)
	mustSymlink(t, "real", filepath.Join(dir, dirMarker+"-link"))
	writeFile(t, filepath.Join(dir, dirMarker+"-file"), []byte("x"))
	for _, path := range []string{
		filepath.Join(dir, dirMarker+"-link"),
		filepath.Join(dir, dirMarker+"-file"),
		filepath.Join(dir, dirMarker+"-missing"),
	} {
		_, _, err := OpenDirRoot(path)
		assertSafeErrorText(t, err, dir)
	}
}

func assertSafeErrorText(t *testing.T, err error, extra ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	text := strings.ToLower(err.Error())
	for _, bad := range append([]string{
		strings.ToLower(dirMarker), "no such file", "permission denied", "too many levels",
	}, extra...) {
		if strings.Contains(text, strings.ToLower(bad)) {
			t.Errorf("error %q contains %q", err.Error(), bad)
		}
	}
}

// childFixture is a root holding the directory "victim" and its Lstat result,
// taken before the test swaps the entry.
type childFixture struct {
	dir  string
	root *os.Root
	want fs.FileInfo
}

func newChildFixture(t *testing.T) childFixture {
	t.Helper()
	dir := tempDir(t)
	mustMkdir(t, filepath.Join(dir, "victim"))
	mustMkdir(t, filepath.Join(dir, "other"))
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	want, err := r.Lstat("victim")
	if err != nil {
		t.Fatal(err)
	}
	return childFixture{dir: dir, root: r, want: want}
}

func (c childFixture) victim() string { return filepath.Join(c.dir, "victim") }

func (c childFixture) open(t *testing.T, name string) (f *os.File, r *os.Root, err error) {
	t.Helper()
	withTimeout(t, func() { f, r, err = OpenChildDir(c.root, name, c.want) })
	return f, r, err
}

func TestOpenChildDirOpensDirectory(t *testing.T) {
	c := newChildFixture(t)
	writeFile(t, filepath.Join(c.victim(), "a"), []byte("x"))

	f, r, err := c.open(t, "victim")
	if err != nil {
		t.Fatal(err)
	}
	defer closeDirRoot(f, r)

	names, err := f.Readdirnames(-1)
	if err != nil || len(names) != 1 || names[0] != "a" {
		t.Errorf("Readdirnames = %v, %v; want [a]", names, err)
	}
	if _, err := r.Lstat("a"); err != nil {
		t.Errorf("child root.Lstat: %v", err)
	}
}

// childSwaps replace "victim" after the caller's Lstat. Each must give ErrChanged.
func childSwaps() map[string]func(t *testing.T, c childFixture) {
	replace := func(t *testing.T, c childFixture, create func(path string)) {
		t.Helper()
		// Rename, not remove: the old directory keeps its inode, so a new
		// directory cannot reuse it and fake an identical identity.
		if err := os.Rename(c.victim(), filepath.Join(c.dir, "moved")); err != nil {
			t.Fatal(err)
		}
		create(c.victim())
	}
	return map[string]func(*testing.T, childFixture){
		"fifo": func(t *testing.T, c childFixture) {
			replace(t, c, func(p string) { mustFIFO(t, p) })
		},
		"symlink to fifo": func(t *testing.T, c childFixture) {
			mustFIFO(t, filepath.Join(c.dir, "fifo"))
			replace(t, c, func(p string) { mustSymlink(t, "fifo", p) })
		},
		"in-root symlink to directory": func(t *testing.T, c childFixture) {
			replace(t, c, func(p string) { mustSymlink(t, "other", p) })
		},
		"escaping symlink": func(t *testing.T, c childFixture) {
			replace(t, c, func(p string) { mustSymlink(t, "..", p) })
		},
		"different directory": func(t *testing.T, c childFixture) {
			replace(t, c, func(p string) { mustMkdir(t, p) })
		},
		"regular file": func(t *testing.T, c childFixture) {
			replace(t, c, func(p string) { writeFile(t, p, []byte("x")) })
		},
		"removed": func(t *testing.T, c childFixture) {
			if err := os.Remove(c.victim()); err != nil {
				t.Fatal(err)
			}
		},
	}
}

func TestOpenChildDirDetectsSwap(t *testing.T) {
	for name, swap := range childSwaps() {
		t.Run(name, func(t *testing.T) {
			c := newChildFixture(t)
			swap(t, c)
			f, r, err := c.open(t, "victim")
			closeDirRoot(f, r)
			if !errors.Is(err, ErrChanged) {
				t.Errorf("error = %v, want ErrChanged", err)
			}
			if f != nil || r != nil {
				t.Error("returned a handle with an error")
			}
		})
	}
}

// O_DIRECTORY's unique job: refuse a FIFO before opening it. O_NONBLOCK and
// the SameFile check also reject the FIFO, but only after a read-only open has
// succeeded, which would release a writer blocked in open(2).
func TestOpenChildDirDoesNotOpenFIFO(t *testing.T) {
	c := newChildFixture(t)
	if err := os.Rename(c.victim(), filepath.Join(c.dir, "moved")); err != nil {
		t.Fatal(err)
	}
	mustFIFO(t, c.victim())

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		w, err := os.OpenFile(c.victim(), os.O_WRONLY, 0) // blocks until a reader opens
		if err == nil {
			_ = w.Close()
		}
	}()
	time.Sleep(100 * time.Millisecond) // let the writer reach open(2)

	f, r, err := c.open(t, "victim")
	closeDirRoot(f, r)
	if !errors.Is(err, ErrChanged) {
		t.Errorf("error = %v, want ErrChanged", err)
	}
	select {
	case <-writerDone:
		t.Error("OpenChildDir opened the FIFO and released the writer")
	case <-time.After(200 * time.Millisecond):
	}

	rd, err := os.OpenFile(c.victim(), os.O_RDONLY|syscall.O_NONBLOCK, 0) // release the writer
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }()
	select {
	case <-writerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("writer still blocked")
	}
}

func TestOpenChildDirClosedParentIsNotChanged(t *testing.T) {
	c := newChildFixture(t)
	_ = c.root.Close()
	_, _, err := c.open(t, "victim")
	if err == nil || errors.Is(err, ErrChanged) {
		t.Errorf("error = %v, want a non-ErrChanged failure", err)
	}
	assertSafeErrorText(t, err, c.dir)
}

func TestOpenDirRootRejectsEmptyAndNULPaths(t *testing.T) {
	for _, path := range []string{"", "a\x00b", "\x00"} {
		f, r, err := OpenDirRoot(path)
		closeDirRoot(f, r)
		if err == nil || f != nil || r != nil {
			t.Errorf("OpenDirRoot(%q) = %v, %v, %v; want error and nil handles", path, f, r, err)
		}
		if errors.Is(err, ErrSymlink) || errors.Is(err, ErrNotDir) {
			t.Errorf("OpenDirRoot(%q) error = %v, want a plain open failure", path, err)
		}
	}
}

func TestOpenChildDirRejectsInvalidNames(t *testing.T) {
	c := newChildFixture(t)
	for _, name := range []string{"", ".", "..", "a/b", "/victim", "victim/", "a\x00b"} {
		f, r, err := OpenChildDir(c.root, name, c.want)
		closeDirRoot(f, r)
		if !errors.Is(err, ErrInvalidName) {
			t.Errorf("name %q: error = %v, want ErrInvalidName", name, err)
		}
	}
}

func TestOpenChildDirErrorTextHasNoPathOrOSText(t *testing.T) {
	c := newChildFixture(t)
	mustSymlink(t, "..", filepath.Join(c.dir, dirMarker+"-escape"))
	mustFIFO(t, filepath.Join(c.dir, dirMarker+"-fifo"))
	for _, name := range []string{dirMarker + "-escape", dirMarker + "-fifo", dirMarker + "-missing", dirMarker + "/x"} {
		_, _, err := OpenChildDir(c.root, name, c.want)
		assertSafeErrorText(t, err, c.dir)
	}
}

func TestOpenChildDirDoesNotLeakDescriptors(t *testing.T) {
	attempts := map[string]func(t *testing.T){
		"success": func(t *testing.T) {
			c := newChildFixture(t)
			defer func() { _ = c.root.Close() }()
			f, r, err := c.open(t, "victim")
			if err != nil {
				t.Fatal(err)
			}
			closeDirRoot(f, r)
		},
		"invalid name": func(t *testing.T) {
			c := newChildFixture(t)
			defer func() { _ = c.root.Close() }()
			_, _, _ = OpenChildDir(c.root, "..", c.want)
		},
		"OpenDirRoot success": func(t *testing.T) {
			f, r, err := OpenDirRoot(tempDir(t))
			if err != nil {
				t.Fatal(err)
			}
			closeDirRoot(f, r)
		},
	}
	for name, setup := range map[string]func(t *testing.T, dir string) string{
		"OpenDirRoot file": func(t *testing.T, dir string) string {
			writeFile(t, filepath.Join(dir, "x"), []byte("x"))
			return filepath.Join(dir, "x")
		},
		"OpenDirRoot fifo": func(t *testing.T, dir string) string {
			mustFIFO(t, filepath.Join(dir, "x"))
			return filepath.Join(dir, "x")
		},
		"OpenDirRoot symlink root": func(t *testing.T, dir string) string {
			mustMkdir(t, filepath.Join(dir, "real"))
			mustSymlink(t, "real", filepath.Join(dir, "x"))
			return filepath.Join(dir, "x")
		},
		"OpenDirRoot symlinked parent": func(t *testing.T, dir string) string {
			mustMkdir(t, filepath.Join(dir, "real"))
			mustMkdir(t, filepath.Join(dir, "real", "sub"))
			mustSymlink(t, "real", filepath.Join(dir, "x"))
			return filepath.Join(dir, "x", "sub")
		},
		"OpenDirRoot missing": func(t *testing.T, dir string) string {
			return filepath.Join(dir, "x")
		},
		"OpenDirRoot empty": func(*testing.T, string) string { return "" },
	} {
		attempts[name] = func(t *testing.T) {
			f, r, _ := OpenDirRoot(setup(t, tempDir(t)))
			closeDirRoot(f, r)
		}
	}
	for name, swap := range childSwaps() {
		attempts["swap "+name] = func(t *testing.T) {
			c := newChildFixture(t)
			defer func() { _ = c.root.Close() }()
			swap(t, c)
			f, r, _ := c.open(t, "victim")
			closeDirRoot(f, r)
		}
	}
	for name, attempt := range attempts {
		t.Run(name, func(t *testing.T) {
			attempt(t) // warm up lazily created descriptors (poller, etc.)
			before := fdCount(t)
			for range 20 {
				attempt(t)
			}
			if after := fdCount(t); after != before {
				t.Errorf("descriptors before = %d, after = %d", before, after)
			}
		})
	}
}
