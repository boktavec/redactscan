//go:build darwin || linux

package safefs

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// inRoot returns a temp directory and a Root for it.
func inRoot(t *testing.T) (string, *os.Root) {
	t.Helper()
	dir := tempDir(t)
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return dir, r
}

func openInTimed(t *testing.T, r *os.Root, name string) (f *os.File, err error) {
	t.Helper()
	withTimeout(t, func() { f, err = OpenRegularIn(r, name) })
	return f, err
}

func TestOpenRegularInReadsRegularFile(t *testing.T) {
	dir, r := inRoot(t)
	writeFile(t, filepath.Join(dir, "a"), []byte("hello"))
	f, err := openInTimed(t, r, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 5)
	if n, err := f.Read(buf); err != nil || string(buf[:n]) != "hello" {
		t.Errorf("Read = %q, %v", buf[:n], err)
	}
	flags, err := fcntlGetFl(f)
	if err != nil {
		t.Fatal(err)
	}
	if flags&syscall.O_NONBLOCK != 0 {
		t.Error("returned file is still non-blocking")
	}
}

func mustRename(t *testing.T, from, to string) {
	t.Helper()
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}
}

func fcntlGetFl(f *os.File) (int, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var flags uintptr
	var errno syscall.Errno
	if err := rc.Control(func(fd uintptr) {
		flags, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
	}); err != nil {
		return 0, err
	}
	if errno != 0 {
		return 0, errno
	}
	return int(flags), nil
}

func TestOpenRegularInRefusals(t *testing.T) {
	dir, r := inRoot(t)
	mustMkdir(t, filepath.Join(dir, "dir"))
	writeFile(t, filepath.Join(dir, "real"), []byte("x"))
	mkfifo(t, filepath.Join(dir, "fifo"))
	mustSymlink(t, "real", filepath.Join(dir, "link"))
	mustSymlink(t, "missing", filepath.Join(dir, "dangling"))
	mustSymlink(t, "/etc/hosts", filepath.Join(dir, "escape"))

	tests := []struct {
		name, file string
		want       error
	}{
		{"symlink", "link", ErrSymlink},
		{"dangling symlink", "dangling", ErrSymlink},
		{"escaping symlink", "escape", ErrSymlink},
		{"fifo", "fifo", ErrNotRegular},
		{"directory", "dir", ErrNotRegular},
		{"missing", "missing", os.ErrNotExist},
		{"empty", "", ErrInvalidName},
		{"dot", ".", ErrInvalidName},
		{"dotdot", "..", ErrInvalidName},
		{"slash", "dir/x", ErrInvalidName},
		{"nul", "a\x00b", ErrInvalidName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := openInTimed(t, r, tt.file)
			if f != nil {
				_ = f.Close()
				t.Error("returned a handle with an error")
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

// Swap the victim between Lstat and open; the open must not return the
// substitute.
func TestOpenRegularInDetectsSwap(t *testing.T) {
	swaps := map[string]func(t *testing.T, dir string){
		"other file": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "other"), []byte("y"))
			mustRename(t, filepath.Join(dir, "other"), filepath.Join(dir, "victim"))
		},
		"symlink to other file": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "other"), []byte("y"))
			_ = os.Remove(filepath.Join(dir, "victim"))
			mustSymlink(t, "other", filepath.Join(dir, "victim"))
		},
		"fifo": func(t *testing.T, dir string) {
			_ = os.Remove(filepath.Join(dir, "victim"))
			mkfifo(t, filepath.Join(dir, "victim"))
		},
	}
	for name, swap := range swaps {
		t.Run(name, func(t *testing.T) {
			dir, r := inRoot(t)
			writeFile(t, filepath.Join(dir, "victim"), []byte("x"))
			afterLstat = func() { swap(t, dir) }
			t.Cleanup(func() { afterLstat = func() {} })

			f, err := openInTimed(t, r, "victim")
			if f != nil {
				_ = f.Close()
				t.Error("returned a handle after a swap")
			}
			if !errors.Is(err, ErrChanged) && !errors.Is(err, ErrNotRegular) {
				t.Errorf("error = %v, want ErrChanged or ErrNotRegular", err)
			}
		})
	}
}

func TestOpenRegularInRefusesForeignOwner(t *testing.T) {
	dir, r := inRoot(t)
	writeFile(t, filepath.Join(dir, "a"), []byte("x"))
	real := geteuid
	geteuid = func() int { return real() + 1 }
	t.Cleanup(func() { geteuid = real })

	f, err := openInTimed(t, r, "a")
	if f != nil {
		_ = f.Close()
		t.Error("returned a handle for a foreign-owned file")
	}
	if !errors.Is(err, ErrNotOwned) {
		t.Errorf("error = %v, want ErrNotOwned", err)
	}
}

func TestOpenRegularInErrorTextHasNoPathOrOSText(t *testing.T) {
	dir, r := inRoot(t)
	mustSymlink(t, "real", filepath.Join(dir, dirMarker+"-link"))
	mkfifo(t, filepath.Join(dir, dirMarker+"-fifo"))
	for _, name := range []string{dirMarker + "-link", dirMarker + "-fifo", dirMarker + "-missing"} {
		_, err := openInTimed(t, r, name)
		assertSafeErrorText(t, err, dir)
	}
}
