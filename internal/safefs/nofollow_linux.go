package safefs

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// normalizePath is the identity on Linux; there are no system links to allow.
func normalizePath(path string) string { return path }

// openNoFollow opens path with flags, refusing a symlink in any component as
// typed. It walks the components with openat so each directory is opened
// relative to the previous descriptor with O_NOFOLLOW. A relative path starts
// at ".", so the current directory itself is not re-checked.
func openNoFollow(path string, flags int) (*os.File, error) {
	var parts []string
	for _, p := range strings.Split(path, "/") {
		if p != "" && p != "." {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return nil, syscall.ENOENT
	}

	start := "."
	if strings.HasPrefix(path, "/") {
		start = "/"
	}
	dirfd, err := retryEINTR(func() (int, error) {
		return syscall.Open(start, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	})
	if err != nil {
		return nil, err
	}

	for i, part := range parts[:len(parts)-1] {
		next, err := retryEINTR(func() (int, error) {
			return syscall.Openat(dirfd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		})
		if err != nil {
			err = classifyDirOpenError(start, parts[:i+1], err)
			_ = syscall.Close(dirfd)
			return nil, err
		}
		_ = syscall.Close(dirfd)
		dirfd = next
	}

	fd, err := retryEINTR(func() (int, error) {
		return syscall.Openat(dirfd, parts[len(parts)-1], flags|syscall.O_CLOEXEC, 0)
	})
	_ = syscall.Close(dirfd)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// retryEINTR repeats a raw syscall interrupted by a signal; package os does
// this for os.OpenFile, but the walk calls syscall directly.
func retryEINTR(open func() (int, error)) (int, error) {
	for {
		fd, err := open()
		if err != syscall.EINTR {
			return fd, err
		}
	}
}

// classifyDirOpenError maps a failed directory open to ELOOP when the
// component is a symlink. Verified in a golang:1.27 container: Linux reports
// ENOTDIR (not ELOOP) for O_DIRECTORY|O_NOFOLLOW on a symlink. The Lstat of
// the typed prefix (start joined with parts) only picks which refusal is
// reported; a race can change that label but the open has already failed, so
// it still fails closed. (syscall.Fstatat is not available on every Linux
// architecture.)
func classifyDirOpenError(start string, parts []string, err error) error {
	if err != syscall.ENOTDIR {
		return err
	}
	var st syscall.Stat_t
	prefix := filepath.Join(start, filepath.Join(parts...))
	if syscall.Lstat(prefix, &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
		return syscall.ELOOP
	}
	return err
}
