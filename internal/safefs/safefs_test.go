//go:build darwin || linux

package safefs

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const marker = "MARKER-file-content-5c1e"

// tempDir returns a symlink-free temp directory (macOS TempDir lives under
// the /var symlink, which PR 2 treats specially).
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mkfifo(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

// openWithTimeout fails the test if OpenRegular blocks.
func openWithTimeout(t *testing.T, path string) (*os.File, error) {
	t.Helper()
	type res struct {
		f   *os.File
		err error
	}
	ch := make(chan res, 1)
	go func() {
		f, err := OpenRegular(path)
		ch <- res{f, err}
	}()
	select {
	case r := <-ch:
		return r.f, r.err
	case <-time.After(2 * time.Second):
		t.Fatal("OpenRegular blocked")
		return nil, nil
	}
}

// setHook installs a swap hook for one test; hook tests must not be parallel.
func setHook(t *testing.T, fn func()) {
	t.Helper()
	afterLstat = fn
	t.Cleanup(func() { afterLstat = func() {} })
}

func mustRemoveAndReplace(t *testing.T, path string, replace func()) func() {
	return func() {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
		replace()
	}
}

func TestOpenRegularReadsWholeFile(t *testing.T) {
	// 1 MiB crosses the 64 KiB read-buffer size used by io.ReadAll growth.
	want := bytes.Repeat([]byte("0123456789abcdef"), 64*1024)
	path := filepath.Join(tempDir(t), "big.log")
	writeFile(t, path, want)

	f, err := OpenRegular(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("read %d bytes, want %d identical bytes", len(got), len(want))
	}
}

func TestOpenRegularReturnsBlockingFile(t *testing.T) {
	path := filepath.Join(tempDir(t), "a.log")
	writeFile(t, path, []byte(marker))

	f, err := OpenRegular(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags uintptr
	var errno syscall.Errno
	if err := rc.Control(func(fd uintptr) {
		flags, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
	}); err != nil {
		t.Fatal(err)
	}
	if errno != 0 {
		t.Fatalf("F_GETFL: %v", errno)
	}
	if flags&syscall.O_NONBLOCK != 0 {
		t.Error("returned file is still O_NONBLOCK")
	}
}

// refusalCases builds every input that OpenRegular must refuse, each with the
// check that identifies the refusal.
type refusalCase struct {
	name  string
	setup func(t *testing.T, dir string) string
	check func(t *testing.T, err error)
}

func isSymlink(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrSymlink) {
		t.Errorf("err = %v, want ErrSymlink", err)
	}
}

func isNotRegular(want FileType) func(*testing.T, error) {
	return func(t *testing.T, err error) {
		t.Helper()
		var nre *NotRegularError
		if !errors.Is(err, ErrNotRegular) || !errors.As(err, &nre) || nre.Type != want {
			t.Errorf("err = %v, want NotRegularError(%s)", err, want)
		}
	}
}

func refusalCases(t *testing.T) []refusalCase {
	return []refusalCase{
		{"symlink to file", func(t *testing.T, dir string) string {
			target := filepath.Join(dir, "target")
			writeFile(t, target, []byte(marker))
			link := filepath.Join(dir, "link-file")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return link
		}, isSymlink},
		{"symlink to directory", func(t *testing.T, dir string) string {
			link := filepath.Join(dir, "link-dir")
			if err := os.Symlink(dir, link); err != nil {
				t.Fatal(err)
			}
			return link
		}, isSymlink},
		{"dangling symlink", func(t *testing.T, dir string) string {
			link := filepath.Join(dir, "link-dangling")
			if err := os.Symlink(filepath.Join(dir, "missing-target"), link); err != nil {
				t.Fatal(err)
			}
			return link
		}, isSymlink},
		{"directory", func(t *testing.T, dir string) string { return dir }, isNotRegular(TypeDirectory)},
		{"fifo", func(t *testing.T, dir string) string {
			p := filepath.Join(dir, "fifo")
			mkfifo(t, p)
			return p
		}, isNotRegular(TypeFIFO)},
		{"device", func(*testing.T, string) string { return os.DevNull }, isNotRegular(TypeDevice)},
		{"socket", func(t *testing.T, _ string) string {
			// Unix socket paths are limited to about 100 bytes, so avoid long temp dirs.
			dir, err := os.MkdirTemp("/tmp", "sf")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			p := filepath.Join(dir, "s")
			l, err := net.Listen("unix", p)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = l.Close() })
			return p
		}, isNotRegular(TypeSocket)},
	}
}

func TestOpenRegularRefusals(t *testing.T) {
	for _, tc := range refusalCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.setup(t, tempDir(t))
			f, err := openWithTimeout(t, path)
			if err == nil {
				_ = f.Close()
				t.Fatal("OpenRegular succeeded, want refusal")
			}
			if f != nil {
				t.Error("non-nil file returned with error")
			}
			tc.check(t, err)
		})
	}
}

// swapCases replace the file between Lstat and open.
func swapCases(t *testing.T) []struct {
	name  string
	swap  func(path string)
	check func(*testing.T, error)
} {
	other := filepath.Join(tempDir(t), "other")
	writeFile(t, other, []byte("other"))
	isChanged := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, ErrChanged) {
			t.Errorf("err = %v, want ErrChanged", err)
		}
	}
	return []struct {
		name  string
		swap  func(path string)
		check func(*testing.T, error)
	}{
		{"to symlink", func(p string) { _ = os.Symlink(other, p) }, isSymlink},
		{"to other regular file", func(p string) { _ = os.WriteFile(p, []byte("x"), 0o600) }, isChanged},
		{"to fifo", func(p string) { _ = syscall.Mkfifo(p, 0o600) }, isChanged},
	}
}

func TestOpenRegularDetectsSwapAfterLstat(t *testing.T) {
	for _, tc := range swapCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(tempDir(t), "victim")
			writeFile(t, path, []byte(marker))
			setHook(t, mustRemoveAndReplace(t, path, func() { tc.swap(path) }))

			f, err := openWithTimeout(t, path)
			if err == nil {
				_ = f.Close()
				t.Fatal("OpenRegular succeeded after swap")
			}
			tc.check(t, err)
			if _, statErr := os.Lstat(path); statErr != nil {
				t.Errorf("swap did not happen: %v", statErr)
			}
		})
	}
}

func TestOpenRegularDetectsSwapToDeviceHardLink(t *testing.T) {
	path := filepath.Join(tempDir(t), "victim")
	writeFile(t, path, []byte(marker))
	setHook(t, mustRemoveAndReplace(t, path, func() {
		if err := os.Link(os.DevNull, path); err != nil {
			t.Skipf("cannot hard link %s: %v", os.DevNull, err)
		}
	}))

	f, err := OpenRegular(path)
	if err == nil {
		_ = f.Close()
		t.Fatal("OpenRegular succeeded after swap")
	}
	if !errors.Is(err, ErrChanged) {
		t.Errorf("err = %v, want ErrChanged", err)
	}
}

func TestOpenRegularOSErrorsStayInspectable(t *testing.T) {
	dir := tempDir(t)

	t.Run("missing", func(t *testing.T) {
		_, err := OpenRegular(filepath.Join(dir, "missing"))
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("err = %v, want fs.ErrNotExist", err)
		}
	})
	t.Run("permission denied", func(t *testing.T) {
		path := filepath.Join(dir, "locked")
		writeFile(t, path, []byte(marker))
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		if f, err := os.Open(path); err == nil {
			_ = f.Close()
			t.Skip("file is readable (running as root?)")
		}
		_, err := OpenRegular(path)
		if !errors.Is(err, fs.ErrPermission) {
			t.Errorf("err = %v, want fs.ErrPermission", err)
		}
	})
}

// Every error must be free of the path, file contents and OS error text.
func TestErrorTextLeaksNothing(t *testing.T) {
	dir := tempDir(t)
	var paths []string
	var errs []error
	record := func(path string, err error) {
		paths = append(paths, path)
		errs = append(errs, err)
	}

	for _, tc := range refusalCases(t) {
		path := tc.setup(t, dir)
		_, err := openWithTimeout(t, path)
		record(path, err)
	}
	_, err := OpenRegular(filepath.Join(dir, "missing"))
	record(filepath.Join(dir, "missing"), err)

	locked := filepath.Join(dir, "locked")
	writeFile(t, locked, []byte(marker))
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	lf, err := OpenRegular(locked) // succeeds when running as root
	closeIfOpen(lf, err)
	record(locked, err)

	// A path component that is a regular file: ENOTDIR text must not leak either.
	notDir := filepath.Join(dir, "plain", "child")
	writeFile(t, filepath.Join(dir, "plain"), []byte(marker))
	_, err = OpenRegular(notDir)
	record(notDir, err)

	forbidden := []string{marker, dir, "no such file", "permission denied", "too many levels", "not a directory"}
	for i, err := range errs {
		if err == nil {
			continue
		}
		for _, bad := range append(forbidden, paths[i]) {
			if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(bad)) {
				t.Errorf("error %q contains %q", err.Error(), bad)
			}
		}
	}
}

func closeIfOpen(f *os.File, _ error) {
	if f != nil {
		_ = f.Close()
	}
}

func fdCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestOpenRegularLeaksNoDescriptors(t *testing.T) {
	dir := tempDir(t)
	attempts := map[string]func(t *testing.T){}
	for _, tc := range refusalCases(t) {
		path := tc.setup(t, dir)
		attempts[tc.name] = func(t *testing.T) { closeIfOpen(openWithTimeout(t, path)) }
	}
	attempts["missing"] = func(*testing.T) { _, _ = OpenRegular(filepath.Join(dir, "missing")) }
	for _, tc := range swapCases(t) {
		attempts["swap "+tc.name] = func(t *testing.T) {
			path := filepath.Join(dir, "victim")
			writeFile(t, path, []byte(marker))
			setHook(t, mustRemoveAndReplace(t, path, func() { tc.swap(path) }))
			closeIfOpen(openWithTimeout(t, path))
			_ = os.Remove(path)
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
