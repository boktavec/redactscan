//go:build darwin || linux

package safefs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
)

const (
	outputMode   = 0o600
	maxTempTries = 10
)

// Test seams. Tests in this package replace them to swap directories, plant
// temp names or inject I/O failures; production never changes them.
var (
	beforeOpenRoot = func() {}
	beforeCommit   = func() {}
	tempName       = randomTempName
	wrapTemp       = func(f *os.File) tempFile { return f }
	removeEntry    = func(r *os.Root, name string) error { return r.Remove(name) }
)

// tempFile is the part of *os.File that WriteSibling uses after creation.
type tempFile interface {
	io.Writer
	Sync() error
	Close() error
}

func randomTempName() string {
	var b [8]byte
	_, _ = rand.Read(b[:]) // never fails since Go 1.24 (it crashes instead)
	return ".redactscan-" + hex.EncodeToString(b[:]) + ".tmp"
}

// WriteSibling writes data to a new file named outName in the directory that
// holds the input file at inputPath (the path as typed). input is the FileInfo
// of the already-open input descriptor. outName must be a single path
// component. With replace false an existing outName is never replaced; with
// replace true a regular file is replaced atomically. On error nothing is
// created or replaced. tempLeft reports that the temp file could not be
// removed (on success or failure).
//
// The directory is opened without following symlinks, pinned as an os.Root
// after a SameFile check, and bound to the input's inode. Every later
// operation is a single-component call relative to that root, so a directory
// swapped during the write cannot redirect the output.
func WriteSibling(inputPath string, input fs.FileInfo, outName string, data []byte, replace bool) (tempLeft bool, err error) {
	if outName == "" || outName == "." || outName == ".." || strings.ContainsAny(outName, "/\x00") {
		return false, ErrInvalidName
	}
	dir, base, ok := splitTyped(normalizePath(inputPath))
	if !ok || outName == base {
		return false, ErrInvalidName
	}

	dirFile, err := openDir(dir)
	if err != nil {
		if isSymlinkRefusal(dir, err) {
			return false, ErrSymlink
		}
		return false, newOpError("open dir", err)
	}
	defer func() { _ = dirFile.Close() }()

	beforeOpenRoot()
	root, err := rootFromDir(dirFile)
	if err != nil {
		return false, err
	}
	defer func() { _ = root.Close() }()

	inFi, err := root.Lstat(base)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, ErrChanged
		}
		return false, newOpError("lstat", err)
	}
	if !os.SameFile(inFi, input) {
		return false, ErrChanged
	}

	if err := checkDestination(root, outName, replace); err != nil {
		return false, err
	}

	temp, tempLeft, err := writeTemp(root, data)
	if err != nil {
		return tempLeft, err
	}

	beforeCommit()

	if !dirUnchanged(dir, root) {
		return removeEntry(root, temp) != nil, ErrChanged
	}
	if replace {
		if err := root.Rename(temp, outName); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				// Rename onto a directory reports EEXIST; with replace that is
				// a destination that is no longer replaceable, not "exists".
				err = ErrChanged
			} else {
				err = newOpError("rename", err)
			}
			return removeEntry(root, temp) != nil, err
		}
		_ = dirFile.Sync() // best effort: the rename is already durable in the cache
		return false, nil
	}
	if err := root.Link(temp, outName); err != nil {
		return removeEntry(root, temp) != nil, newOpError("link", err)
	}
	// The destination exists now and is never touched again; only the temp name is cleaned.
	tempLeft = removeEntry(root, temp) != nil
	_ = dirFile.Sync()
	return tempLeft, nil
}

// splitTyped splits at the last "/" without cleaning: "app.log" has dir ".",
// "/app.log" has dir "/". ok is false when the base is empty.
func splitTyped(path string) (dir, base string, ok bool) {
	i := strings.LastIndexByte(path, '/')
	switch {
	case i < 0:
		dir, base = ".", path
	case i == 0:
		dir, base = "/", path[1:]
	default:
		dir, base = path[:i], path[i+1:]
	}
	return dir, base, base != ""
}

func openDir(dir string) (*os.File, error) {
	return openNoFollow(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW)
}

// isSymlinkRefusal reports whether a failed directory open hit a symlink.
// Linux reports ENOTDIR instead of ELOOP for a symlink as the last component,
// so that case is told apart with an Lstat; it only picks the refusal label.
func isSymlinkRefusal(dir string, err error) bool {
	if errors.Is(err, syscall.ELOOP) {
		return true
	}
	if !errors.Is(err, syscall.ENOTDIR) {
		return false
	}
	fi, lerr := os.Lstat(dir)
	return lerr == nil && fi.Mode()&fs.ModeSymlink != 0
}

func sameAsRoot(dirFile *os.File, root *os.Root) bool {
	a, err := dirFile.Stat()
	if err != nil {
		return false
	}
	b, err := root.Stat(".")
	return err == nil && os.SameFile(a, b)
}

// dirUnchanged reports whether the typed directory path still names the pinned
// root. Any failure counts as changed (fail closed).
func dirUnchanged(dir string, root *os.Root) bool {
	f, err := openDir(dir)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	return sameAsRoot(f, root)
}

// checkDestination is a UX pre-check; link and rename enforce the rules.
func checkDestination(root *os.Root, outName string, replace bool) error {
	fi, err := root.Lstat(outName)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return newOpError("lstat", err)
	case !replace:
		return newOpError("lstat", syscall.EEXIST)
	case fi.Mode()&fs.ModeSymlink != 0:
		return ErrSymlink
	case !fi.Mode().IsRegular():
		return &NotRegularError{Type: TypeOf(fi.Mode())}
	}
	return nil
}

// writeTemp creates a 0600 temp file in root and fills, syncs and closes it.
// On error the temp file is removed; tempLeft reports a failed removal.
func writeTemp(root *os.Root, data []byte) (name string, tempLeft bool, err error) {
	var f *os.File
	for range maxTempTries {
		name = tempName()
		f, err = root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, outputMode)
		if !errors.Is(err, fs.ErrExist) {
			break
		}
	}
	if errors.Is(err, fs.ErrExist) {
		return "", false, ErrTempNames
	}
	if err != nil {
		return "", false, newOpError("create temp", err)
	}

	fail := func(closed bool, err error) (string, bool, error) {
		if !closed {
			_ = f.Close()
		}
		return "", removeEntry(root, name) != nil, err
	}
	// Chmod on the descriptor: the create mode is subject to umask.
	if err := f.Chmod(outputMode); err != nil {
		return fail(false, newOpError("chmod", err))
	}
	w := wrapTemp(f)
	if n, err := w.Write(data); err != nil {
		return fail(false, newOpError("write", err))
	} else if n != len(data) {
		return fail(false, newOpError("write", io.ErrShortWrite))
	}
	if err := w.Sync(); err != nil {
		return fail(false, newOpError("sync", err))
	}
	if err := w.Close(); err != nil {
		return fail(true, newOpError("close", err))
	}
	return name, false, nil
}
