//go:build darwin || linux

package quarantine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"syscall"

	"github.com/boktavec/redactscan/internal/safefs"
)

const fileModeMask = fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky

// afterMetadataRead runs in Verify after the metadata is accepted and before
// content is opened; tests swap content there. Production never changes it.
var afterMetadataRead = func() {}

// entry is an opened, checked entry directory. The caller closes it.
type entry struct {
	dir  *os.File
	root *os.Root
}

func (e entry) close() {
	_ = e.root.Close()
	_ = e.dir.Close()
}

// Read returns the validated metadata of the entry id. It never repairs
// anything and never returns content bytes: ErrInvalidID (before any I/O),
// ErrNotFound, ErrUnsafeDir (symlink, foreign owner or a mode other than 0700),
// ErrIncomplete (no metadata.json, or content that is missing, not a euid-owned
// 0600 regular file or not metadata.size bytes) or ErrCorruptMetadata. The
// content hash is not checked here; Verify does that.
func (s *Store) Read(id string) (Metadata, error) {
	e, m, err := s.load(id)
	if err != nil {
		return Metadata{}, err
	}
	defer e.close()
	fi, err := e.root.Lstat(contentName)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Metadata{}, ErrIncomplete
	case err != nil:
		return Metadata{}, newOpError("lstat", err)
	case !fi.Mode().IsRegular() || !ownedByEUID(fi) || fi.Mode()&fileModeMask != filePerm || fi.Size() != m.Size:
		return Metadata{}, ErrIncomplete
	}
	return m, nil
}

// Verify re-hashes the content of the entry id against its metadata. The
// metadata must pass the same checks as Read; any content that is missing,
// swapped, or differs in owner, mode, size or SHA-256 is ErrVerifyFailed.
func (s *Store) Verify(id string) error {
	e, m, err := s.load(id)
	if err != nil {
		return err
	}
	defer e.close()
	afterMetadataRead()
	if looseMode(e.root, contentName) {
		return ErrVerifyFailed
	}
	f, err := safefs.OpenRegularIn(e.root, contentName)
	if err != nil {
		return contentOpenError(err)
	}
	defer func() { _ = f.Close() }()
	return verifyContent(f, m)
}

// looseMode reports whether name is a regular file whose mode is not exactly
// 0600. Checked before opening so an unreadable (0000) or tampered file maps
// to a state error, not a raw EACCES. Other states are left to OpenRegularIn.
func looseMode(root *os.Root, name string) bool {
	fi, err := root.Lstat(name)
	return err == nil && fi.Mode().IsRegular() && fi.Mode()&fileModeMask != filePerm
}

// contentOpenError maps a content state problem to ErrVerifyFailed; other OS
// errors keep their bare Errno.
func contentOpenError(err error) error {
	var notRegular *safefs.NotRegularError
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, safefs.ErrSymlink) || errors.Is(err, safefs.ErrChanged) ||
		errors.Is(err, safefs.ErrNotOwned) || errors.As(err, &notRegular) {
		return ErrVerifyFailed
	}
	return err
}

// verifyContent checks the open content file f against m: euid-owned, exactly
// 0600, m.Size bytes, and SHA-256 equal to m.SHA256 (which equals the ID
// prefix). It reads at most m.Size+1 bytes from offset 0 (ReadAt), so the
// descriptor's current offset does not matter and is not moved.
func verifyContent(f *os.File, m Metadata) error {
	fi, err := f.Stat()
	if err != nil {
		return newOpError("fstat", err)
	}
	if !fi.Mode().IsRegular() || !ownedByEUID(fi) || fi.Mode()&fileModeMask != filePerm || fi.Size() != m.Size {
		return ErrVerifyFailed
	}
	h := sha256.New()
	n, err := io.Copy(h, io.NewSectionReader(f, 0, m.Size+1))
	if err != nil {
		return newOpError("read", err)
	}
	if n != m.Size || hex.EncodeToString(h.Sum(nil)) != m.SHA256 {
		return ErrVerifyFailed
	}
	return nil
}

// load validates id, pins and checks the entry directory, and returns its
// strictly decoded metadata. On error nothing is left open.
func (s *Store) load(id string) (entry, Metadata, error) {
	if !ValidID(id) {
		return entry{}, Metadata{}, ErrInvalidID
	}
	e, err := s.openEntry(id)
	if err != nil {
		return entry{}, Metadata{}, err
	}
	m, err := readMetadata(e.root, id)
	if err != nil {
		e.close()
		return entry{}, Metadata{}, err
	}
	return e, m, nil
}

// openEntry pins the entry directory and refuses, never repairs, a symlink, a
// non-directory, a foreign owner or any mode other than exactly 0700.
func (s *Store) openEntry(id string) (entry, error) {
	fi, err := s.qroot.Lstat(id)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return entry{}, ErrNotFound
	case err != nil:
		return entry{}, newOpError("lstat", err)
	case !fi.IsDir() || fi.Mode()&dirModeMask != dirMode:
		return entry{}, ErrUnsafeDir // refused before opening: a 0300 entry must not surface as EACCES
	}
	afterDirLstat(id)
	dir, root, err := safefs.OpenChildDir(s.qroot, id, fi)
	if err != nil {
		if errors.Is(err, safefs.ErrChanged) || errors.Is(err, safefs.ErrSymlink) || errors.Is(err, safefs.ErrNotDir) {
			return entry{}, ErrUnsafeDir
		}
		return entry{}, err
	}
	st, err := dir.Stat()
	if err != nil {
		_ = root.Close()
		_ = dir.Close()
		return entry{}, newOpError("fstat", err)
	}
	if !ownedByEUID(st) || st.Mode()&dirModeMask != dirMode {
		_ = root.Close()
		_ = dir.Close()
		return entry{}, ErrUnsafeDir
	}
	return entry{dir: dir, root: root}, nil
}

// readMetadata reads metadata.json through safefs.OpenRegularIn and decodes it.
func readMetadata(root *os.Root, id string) (Metadata, error) {
	if looseMode(root, metadataName) {
		return Metadata{}, ErrCorruptMetadata
	}
	f, err := safefs.OpenRegularIn(root, metadataName)
	if err != nil {
		var notRegular *safefs.NotRegularError
		switch {
		case errors.Is(err, syscall.ENOENT):
			return Metadata{}, ErrIncomplete
		case errors.Is(err, safefs.ErrSymlink) || errors.Is(err, safefs.ErrChanged) ||
			errors.Is(err, safefs.ErrNotOwned) || errors.As(err, &notRegular):
			return Metadata{}, ErrCorruptMetadata
		}
		return Metadata{}, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return Metadata{}, newOpError("fstat", err)
	}
	if fi.Mode()&fileModeMask != filePerm || fi.Size() > MaxMetadataBytes {
		return Metadata{}, ErrCorruptMetadata
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxMetadataBytes+1))
	if err != nil {
		return Metadata{}, newOpError("read", err)
	}
	return decodeMetadata(data, id)
}
