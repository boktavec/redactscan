//go:build darwin || linux

package safefs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"syscall"
)

// OpenDirRoot opens path as a directory reached without a symlink in any
// typed component (same rules and macOS system-link handling as OpenRegular)
// and returns the verified directory and an os.Root pinned to it. The caller
// closes both. The *os.File is for listing only; it is opened non-blocking so
// the open itself cannot hang.
func OpenDirRoot(path string) (*os.File, *os.Root, error) {
	// openNoFollow drops empty components, so "" would open the current
	// directory on Linux.
	if path == "" || strings.ContainsRune(path, 0) {
		return nil, nil, newOpError("open dir", syscall.ENOENT)
	}
	p := normalizePath(path)
	f, err := openNoFollow(p, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK)
	if err != nil {
		switch {
		case isSymlinkRefusal(p, err):
			return nil, nil, ErrSymlink
		case errors.Is(err, syscall.ENOTDIR):
			return nil, nil, ErrNotDir
		}
		return nil, nil, newOpError("open dir", err)
	}
	return pinRoot(f)
}

// OpenChildDir opens the single component name in parent as a directory and
// returns it and a Root pinned to it, only if it is the same file as want
// (the caller's Lstat result). It never blocks on a FIFO. The caller closes
// both results.
func OpenChildDir(parent *os.Root, name string, want fs.FileInfo) (*os.File, *os.Root, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return nil, nil, ErrInvalidName
	}
	// Never Root.OpenRoot(name): it opens without O_DIRECTORY and O_NONBLOCK,
	// so a directory swapped for a FIFO blocks it forever. O_DIRECTORY turns a
	// FIFO, or a symlink to one, into ENOTDIR.
	f, err := parent.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
	if err != nil {
		// The caller just saw a directory here, so these mean it was swapped.
		if errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP) ||
			errors.Is(err, fs.ErrNotExist) || isRootEscape(err) {
			return nil, nil, ErrChanged
		}
		return nil, nil, newOpError("open dir", err)
	}
	// Root.OpenFile follows an in-root symlink to a directory; identity with
	// the Lstat result catches that swap.
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, newOpError("fstat", err)
	}
	if !os.SameFile(st, want) {
		_ = f.Close()
		return nil, nil, ErrChanged
	}
	return pinRoot(f)
}

// isRootEscape reports whether err is os.Root refusing a path that leaves the
// root. The os package does not export that error; it is the only one a Root
// returns as a *fs.PathError wrapping something other than a syscall.Errno
// (pinned by TestRootEscapeIsNotAnErrno). A closed Root (fs.ErrClosed) and
// fs.ErrInvalid are also non-Errno and are not escapes. Any other non-Errno
// PathError, such as "empty path", counts as an escape.
func isRootEscape(err error) bool {
	var pe *fs.PathError
	var errno syscall.Errno
	if !errors.As(err, &pe) || errors.As(pe.Err, &errno) {
		return false
	}
	return !errors.Is(pe.Err, fs.ErrClosed) && !errors.Is(pe.Err, fs.ErrInvalid)
}

// pinRoot builds the Root for f and closes f on failure.
func pinRoot(f *os.File) (*os.File, *os.Root, error) {
	r, err := rootFromDir(f)
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, r, nil
}

// rootFromDir opens a Root through the verified descriptor, not a path: a path
// would be resolved again, and a directory swapped for a FIFO would hang. The
// SameFile check stays as defense in depth. The caller closes the Root.
func rootFromDir(f *os.File) (*os.Root, error) {
	r, err := os.OpenRoot(fmt.Sprintf("%s/%d", fdDir, f.Fd()))
	if err != nil {
		return nil, newOpError("open root", err)
	}
	if !sameAsRoot(f, r) {
		_ = r.Close()
		return nil, ErrChanged
	}
	return r, nil
}
