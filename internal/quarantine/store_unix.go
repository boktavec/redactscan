//go:build darwin || linux

package quarantine

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/boktavec/redactscan/internal/safefs"
)

// geteuid is a test seam for the root refusal and the owner checks.
var geteuid = os.Geteuid

// afterDirLstat runs between ensureDir's Lstat and open; tests swap the
// directory there (name is the directory being opened). Production never changes it.
var afterDirLstat = func(string) {}

// chmodDir is a test seam for the fchmod repair, to simulate a filesystem
// that ignores chmod.
var chmodDir = func(f *os.File, m fs.FileMode) error { return f.Chmod(m) }

const (
	dirMode     fs.FileMode = 0o700
	dirModeMask             = fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky
	defaultDir              = ".redactscan"
)

// Fixed names reported by Store.Repaired.
const (
	dirBase       = "base"
	dirIncoming   = "incoming"
	dirQuarantine = "quarantine"
	dirScans      = "scans"
)

// Store is an open quarantine store. It is safe for sequential use.
type Store struct {
	opts     Options
	qdir     *os.File // quarantine/, for listing and fsync
	qroot    *os.Root // quarantine/, pinned
	repaired []string
}

// Open creates or verifies <base>/{incoming,quarantine,scans} at exactly
// 0700. An empty base means ~/.redactscan. Directories owned by the current
// user with a looser mode are repaired and reported by Repaired; symlinks and
// foreign owners are refused with ErrUnsafeDir, and euid 0 with
// ErrRunningAsRoot unless opts.AllowRoot. Symlinks above base are allowed.
// A store directory with no owner-read bit (for example 0300) cannot be
// opened: Open fails closed with an open error and does not repair it.
func Open(base string, opts Options) (*Store, error) {
	if geteuid() == 0 && !opts.AllowRoot {
		return nil, ErrRunningAsRoot
	}
	opts, err := opts.withDefaults()
	if err != nil {
		return nil, err
	}
	base, err = resolveBase(base)
	if err != nil {
		return nil, err
	}

	// Split keeps the trailing slash on parent, so a FIFO or file in the
	// parent position makes os.OpenRoot fail with ENOTDIR instead of blocking.
	parent, name := filepath.Split(base)
	proot, err := os.OpenRoot(parent)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOTDIR) {
			return nil, ErrInvalidBase
		}
		return nil, newOpError("open parent", err)
	}
	defer func() { _ = proot.Close() }()

	s := &Store{opts: opts}
	bdir, broot, err := s.ensureDir(proot, name, dirBase)
	if err != nil {
		return nil, err
	}
	_ = bdir.Close()
	defer func() { _ = broot.Close() }()

	for _, sub := range []string{dirIncoming, dirQuarantine, dirScans} {
		d, r, err := s.ensureDir(broot, sub, sub)
		if err != nil {
			_ = s.Close()
			return nil, err
		}
		if sub != dirQuarantine {
			_ = d.Close()
			_ = r.Close()
			continue
		}
		s.qdir, s.qroot = d, r
	}
	markNoIndex(broot)
	return s, nil
}

// resolveBase applies the default and validates base before any I/O.
func resolveBase(base string) (string, error) {
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", ErrInvalidBase
		}
		base = filepath.Join(home, defaultDir)
	}
	if strings.ContainsRune(base, 0) || !filepath.IsAbs(base) || base != filepath.Clean(base) || base == string(filepath.Separator) {
		return "", ErrInvalidBase
	}
	return base, nil
}

// ensureDir creates name in parent if missing, refuses a symlink, a
// non-directory or a foreign owner, and fchmods an own directory to exactly
// 0700, recording kind in s.repaired when it had to. A directory created by
// this call is never reported: the umask is not a finding. The caller closes
// both results.
func (s *Store) ensureDir(parent *os.Root, name, kind string) (*os.File, *os.Root, error) {
	created := true
	if err := parent.Mkdir(name, dirMode); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return nil, nil, newOpError("mkdir", err)
		}
		created = false
	}
	fi, err := parent.Lstat(name)
	if err != nil {
		return nil, nil, newOpError("lstat", err)
	}
	if !fi.IsDir() {
		return nil, nil, ErrUnsafeDir // symlink or not a directory
	}
	afterDirLstat(name)
	f, r, err := safefs.OpenChildDir(parent, name, fi)
	if err != nil {
		if errors.Is(err, safefs.ErrChanged) || errors.Is(err, safefs.ErrSymlink) || errors.Is(err, safefs.ErrNotDir) {
			return nil, nil, ErrUnsafeDir
		}
		return nil, nil, err
	}
	if err := s.pin(f, created, kind); err != nil {
		_ = f.Close()
		_ = r.Close()
		return nil, nil, err
	}
	return f, r, nil
}

// pin checks the owner and mode of the open directory f and repairs the mode
// through the descriptor, never by path.
func (s *Store) pin(f *os.File, created bool, kind string) error {
	fi, err := f.Stat()
	if err != nil {
		return newOpError("fstat", err)
	}
	if !ownedByEUID(fi) {
		return ErrUnsafeDir
	}
	if fi.Mode()&dirModeMask == dirMode {
		return nil
	}
	if err := chmodDir(f, dirMode); err != nil {
		return newOpError("chmod", err)
	}
	// Fail closed on a filesystem that ignores chmod.
	if fi, err = f.Stat(); err != nil {
		return newOpError("fstat", err)
	}
	if fi.Mode()&dirModeMask != dirMode {
		return ErrUnsafeDir
	}
	if !created {
		s.repaired = append(s.repaired, kind)
	}
	return nil
}

func ownedByEUID(fi fs.FileInfo) bool {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(sys.Uid) == geteuid()
}

// Repaired names the store directories whose mode was tightened to 0700 by
// Open: "base", "incoming", "quarantine", "scans".
func (s *Store) Repaired() []string { return slices.Clone(s.repaired) }

// Close releases the store's descriptors. It is safe to call on a partially
// opened store.
func (s *Store) Close() error {
	var err error
	if s.qroot != nil {
		err = s.qroot.Close()
	}
	if s.qdir != nil {
		err = errors.Join(err, s.qdir.Close())
	}
	return err
}
