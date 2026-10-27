//go:build darwin || linux

package safefs

import (
	"errors"
	"os"
	"syscall"
)

// OpenRegular opens path read-only. It returns a blocking *os.File only when
// path names a regular file reached without following a symlink in any
// component (see openNoFollow for the per-OS rule). The caller closes the file.
func OpenRegular(path string) (*os.File, error) {
	path = normalizePath(path)
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, newOpError("lstat", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, ErrSymlink
	}
	if !fi.Mode().IsRegular() {
		return nil, &NotRegularError{Type: TypeOf(fi.Mode())}
	}

	afterLstat()

	// O_NONBLOCK: opening a FIFO swapped in after Lstat must not wait for a
	// writer. O_NOCTTY: a terminal device must not become our controlling tty.
	f, err := openNoFollow(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, ErrSymlink
		}
		return nil, newOpError("open", err)
	}

	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, newOpError("fstat", err)
	}
	if !os.SameFile(fi, st) {
		_ = f.Close()
		return nil, ErrChanged
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, &NotRegularError{Type: TypeOf(st.Mode())}
	}

	// Go never clears an O_NONBLOCK passed to open; restore blocking reads.
	if err := setBlocking(f); err != nil {
		_ = f.Close()
		return nil, newOpError("set blocking", err)
	}
	return f, nil
}

func setBlocking(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	if err := rc.Control(func(fd uintptr) { setErr = syscall.SetNonblock(int(fd), false) }); err != nil {
		return err
	}
	return setErr
}
