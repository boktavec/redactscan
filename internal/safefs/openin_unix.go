//go:build darwin || linux

package safefs

import (
	"io/fs"
	"os"
	"strings"
	"syscall"
)

// geteuid is a test seam for the owner check.
var geteuid = os.Geteuid

// OpenRegularIn opens the single component name in root read-only, only if it
// is a regular file owned by the effective user and is the same file the
// caller's Lstat saw. It never blocks on a FIFO and returns a blocking
// *os.File. The caller closes it.
//
// Root.OpenFile follows an in-root symlink on the final component and ignores
// O_NOFOLLOW (ADR 0004), so the Lstat plus SameFile pair is the symlink guard.
func OpenRegularIn(root *os.Root, name string) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return nil, ErrInvalidName
	}
	fi, err := root.Lstat(name)
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

	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		if isRootEscape(err) {
			return nil, ErrChanged
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
	if !ownedByEUID(st) {
		_ = f.Close()
		return nil, ErrNotOwned
	}
	if err := setBlocking(f); err != nil {
		_ = f.Close()
		return nil, newOpError("set blocking", err)
	}
	return f, nil
}

func ownedByEUID(fi fs.FileInfo) bool {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(sys.Uid) == geteuid()
}
