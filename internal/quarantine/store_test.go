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
	"testing"
	"time"
)

const marker = "MARKER-store-name-5c1e"

// permBits is deliberately independent of the production mask.
const permBits = fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky

var storeDirs = []string{dirIncoming, dirQuarantine, dirScans}

// testOpts lets the suite also run as root (the AllowRoot run).
func testOpts() Options { return Options{AllowRoot: os.Geteuid() == 0} }

// newBase returns a not-yet-created base inside a fresh temp directory.
func newBase(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "store")
}

func openStore(t *testing.T, base string) *Store {
	t.Helper()
	s, err := Open(base, testOpts())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode()
}

func assertDirs0700(t *testing.T, base string) {
	t.Helper()
	for _, p := range append([]string{base}, subdirs(base)...) {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode() & (permBits | fs.ModeDir); got != 0o700|fs.ModeDir {
			t.Errorf("%s mode = %v, want drwx------", filepath.Base(p), got)
		}
		if !ownedByEUID(fi) {
			t.Errorf("%s not owned by euid", filepath.Base(p))
		}
	}
}

func subdirs(base string) []string {
	var out []string
	for _, d := range storeDirs {
		out = append(out, filepath.Join(base, d))
	}
	return out
}

func withUmask(t *testing.T, mask int) {
	t.Helper()
	old := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(old) })
}

func TestOpenCreatesDirectories0700RegardlessOfUmask(t *testing.T) {
	for _, mask := range []int{0o022, 0o077, 0o000} {
		t.Run(fs.FileMode(mask).String(), func(t *testing.T) {
			withUmask(t, mask)
			base := newBase(t)
			s := openStore(t, base)
			assertDirs0700(t, base)
			if len(s.Repaired()) != 0 {
				t.Errorf("Repaired = %v on a fresh store", s.Repaired())
			}
		})
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	base := newBase(t)
	openStore(t, base)
	s := openStore(t, base)
	assertDirs0700(t, base)
	if len(s.Repaired()) != 0 {
		t.Errorf("Repaired = %v for an already-0700 store", s.Repaired())
	}
}

func TestOpenRejectsInvalidBaseBeforeAnyIO(t *testing.T) {
	parent := t.TempDir()
	// Parents exist, so only the base rules can refuse these.
	for _, d := range []string{"a", "store"} {
		if err := os.Mkdir(filepath.Join(parent, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	tests := map[string]string{
		"relative":       "rel",
		"not clean":      parent + "/a/../b",
		"trailing slash": parent + "/store/",
		"root":           "/",
		"nul":            parent + "/x\x00y",
		"missing parent": filepath.Join(parent, "missing", "store"),
	}
	for name, base := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(base, testOpts()); !errors.Is(err, ErrInvalidBase) {
				t.Errorf("error = %v, want ErrInvalidBase", err)
			}
		})
	}
	var names []string
	ents, _ := os.ReadDir(parent)
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"a", "store"}) {
		t.Errorf("parent directory changed: %v", names)
	}
	for _, d := range []string{"a", "store"} {
		if sub, _ := os.ReadDir(filepath.Join(parent, d)); len(sub) != 0 {
			t.Errorf("%s was populated", d)
		}
	}
}

func TestOpenDefaultBaseUsesHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	s, err := Open("", testOpts())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	assertDirs0700(t, filepath.Join(home, ".redactscan"))
}

func TestOpenInvalidHomeIsInvalidBase(t *testing.T) {
	for _, home := range []string{"", "relative"} {
		t.Setenv("HOME", home)
		if _, err := Open("", testOpts()); !errors.Is(err, ErrInvalidBase) {
			t.Errorf("HOME=%q: error = %v, want ErrInvalidBase", home, err)
		}
	}
}

func TestOpenRejectsNegativeOptions(t *testing.T) {
	base := newBase(t)
	if _, err := Open(base, Options{MaxEntries: -1, AllowRoot: true}); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("error = %v, want ErrInvalidOptions", err)
	}
	if _, err := os.Lstat(base); err == nil {
		t.Error("base created despite invalid options")
	}
}

func TestOpenRefusesSymlinks(t *testing.T) {
	for _, victim := range []string{"base", dirIncoming, dirQuarantine, dirScans} {
		t.Run(victim, func(t *testing.T) {
			base := newBase(t)
			target := t.TempDir()
			if err := os.Chmod(target, 0o755); err != nil {
				t.Fatal(err)
			}
			if victim == "base" {
				if err := os.Symlink(target, base); err != nil {
					t.Fatal(err)
				}
			} else {
				openStore(t, base)
				path := filepath.Join(base, victim)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}

			if _, err := Open(base, testOpts()); !errors.Is(err, ErrUnsafeDir) {
				t.Errorf("error = %v, want ErrUnsafeDir", err)
			}
			if got := mode(t, target).Perm(); got != 0o755 {
				t.Errorf("link target mode = %v, want untouched 0755", got)
			}
			if ents, _ := os.ReadDir(target); len(ents) != 0 {
				t.Errorf("link target modified: %v", ents)
			}
		})
	}
}

func TestOpenRefusesNonDirectory(t *testing.T) {
	base := newBase(t)
	if err := os.WriteFile(base, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(base, testOpts()); !errors.Is(err, ErrUnsafeDir) {
		t.Errorf("error = %v, want ErrUnsafeDir", err)
	}
}

func TestOpenAllowsSymlinkAboveBase(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	openStore(t, filepath.Join(link, "store"))
	assertDirs0700(t, filepath.Join(real, "store"))
}

func TestOpenRepairsLooseModes(t *testing.T) {
	loose := map[string]fs.FileMode{
		"0755":   0o755,
		"0750":   0o750,
		"0777":   0o777,
		"1700":   0o700 | fs.ModeSticky,
		"2700":   0o700 | fs.ModeSetgid,
		"setuid": 0o700 | fs.ModeSetuid,
	}
	for _, kind := range []string{"base", dirIncoming, dirQuarantine, dirScans} {
		for name, m := range loose {
			t.Run(kind+"/"+name, func(t *testing.T) {
				base := newBase(t)
				openStore(t, base)
				path := base
				if kind != "base" {
					path = filepath.Join(base, kind)
				}
				if err := os.Chmod(path, m); err != nil {
					t.Fatal(err)
				}
				if got := mode(t, path); got&permBits == 0o700 {
					t.Skipf("filesystem did not keep mode %v", m)
				}

				s := openStore(t, base)
				assertDirs0700(t, base)
				if want := []string{kind}; !slices.Equal(s.Repaired(), want) {
					t.Errorf("Repaired = %v, want %v", s.Repaired(), want)
				}
			})
		}
	}
}

// The uid comparison, without needing root to chown.
func TestOpenRefusesForeignOwnerSeam(t *testing.T) {
	base := newBase(t)
	openStore(t, base)
	real := geteuid
	geteuid = func() int { return real() + 1 }
	t.Cleanup(func() { geteuid = real })

	before := mode(t, base)
	if _, err := Open(base, Options{AllowRoot: true}); !errors.Is(err, ErrUnsafeDir) {
		t.Errorf("error = %v, want ErrUnsafeDir", err)
	}
	if got := mode(t, base); got != before {
		t.Errorf("foreign-owned directory mode changed: %v -> %v", before, got)
	}
}

// Needs root to chown; run with AllowRoot as in spec section 10.
func TestOpenRefusesChownedDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	for _, dir := range []string{"base", dirQuarantine} {
		t.Run(dir, func(t *testing.T) {
			base := newBase(t)
			openStore(t, base)
			path := base
			if dir != "base" {
				path = filepath.Join(base, dir)
			}
			if err := os.Chown(path, 1234, 1234); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(base, Options{AllowRoot: true}); !errors.Is(err, ErrUnsafeDir) {
				t.Errorf("error = %v, want ErrUnsafeDir", err)
			}
			if got := mode(t, path).Perm(); got != 0o700 {
				t.Errorf("mode = %v, want untouched", got)
			}
		})
	}
}

func TestOpenRefusesRootUnlessAllowed(t *testing.T) {
	real := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = real })

	base := newBase(t)
	if _, err := Open(base, Options{}); !errors.Is(err, ErrRunningAsRoot) {
		t.Errorf("error = %v, want ErrRunningAsRoot", err)
	}
	if _, err := os.Lstat(base); err == nil {
		t.Error("base created before the root refusal")
	}

	// With the opt-in the root check passes; under the seam on a non-root
	// host the owner check then refuses (the directories are ours, not
	// root's), which is the fail-closed outcome.
	s, err := Open(base, Options{AllowRoot: true})
	if errors.Is(err, ErrRunningAsRoot) {
		t.Fatal("AllowRoot did not bypass the root refusal")
	}
	if err == nil {
		_ = s.Close()
	} else if os.Geteuid() != 0 && !errors.Is(err, ErrUnsafeDir) {
		t.Errorf("error = %v, want ErrUnsafeDir", err)
	}
}

func TestOpenErrorTextHasNoPathOrOSText(t *testing.T) {
	parent := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(parent, marker+"-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, marker+"-file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	bases := []string{
		filepath.Join(parent, marker+"-link"),
		filepath.Join(parent, marker+"-file"),
		filepath.Join(parent, marker+"-missing", "store"),
		filepath.Join(parent, marker+"-file", "store"),
		"relative-" + marker,
	}
	for _, base := range bases {
		_, err := Open(base, testOpts())
		if err == nil {
			t.Fatalf("Open(%q) succeeded", base)
		}
		text := strings.ToLower(err.Error())
		for _, bad := range []string{strings.ToLower(marker), strings.ToLower(parent), "no such file", "not a directory", "permission denied"} {
			if strings.Contains(text, bad) {
				t.Errorf("error %q contains %q", err.Error(), bad)
			}
		}
	}
}

func TestCloseIsSafeOnZeroStore(t *testing.T) {
	if err := (&Store{}).Close(); err != nil {
		t.Errorf("Close = %v", err)
	}
}

func TestOpenFailsClosedWhenChmodIsIgnored(t *testing.T) {
	base := newBase(t)
	openStore(t, base)
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	real := chmodDir
	chmodDir = func(*os.File, fs.FileMode) error { return nil }
	t.Cleanup(func() { chmodDir = real })

	s, err := Open(base, testOpts())
	if !errors.Is(err, ErrUnsafeDir) {
		t.Errorf("error = %v, want ErrUnsafeDir", err)
	}
	if s != nil {
		_ = s.Close()
		t.Error("returned a store with an error")
	}
}

func TestOpErrorUnwrapsToBareErrno(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	_, err := Open(filepath.Join(parent, "store"), testOpts())
	var pe *fs.PathError
	if err == nil || errors.As(err, &pe) || !errors.Is(err, syscall.EACCES) {
		t.Errorf("error = %v, want a bare EACCES opError", err)
	}
}

// A swap between ensureDir's Lstat and open is safefs.ErrChanged; Open must
// report ErrUnsafeDir.
func TestOpenMapsSwapDuringOpenToUnsafeDir(t *testing.T) {
	swaps := map[string]func(t *testing.T, path string){
		"symlink to other dir": func(t *testing.T, path string) {
			if err := os.Symlink(t.TempDir(), path); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, path string) {
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"other dir": func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, swap := range swaps {
		t.Run(name, func(t *testing.T) {
			base := newBase(t)
			openStore(t, base)
			victim := filepath.Join(base, dirQuarantine)
			afterDirLstat = func(name string) {
				if name != dirQuarantine {
					return
				}
				if err := os.Rename(victim, victim+".moved"); err != nil {
					t.Error(err)
					return
				}
				swap(t, victim)
			}
			t.Cleanup(func() { afterDirLstat = func(string) {} })

			done := make(chan error, 1)
			go func() { _, err := Open(base, testOpts()); done <- err }()
			select {
			case err := <-done:
				if !errors.Is(err, ErrUnsafeDir) {
					t.Errorf("error = %v, want ErrUnsafeDir", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Open blocked")
			}
		})
	}
}

func TestOpErrorStripsWrappers(t *testing.T) {
	for name, wrapped := range map[string]error{
		"PathError":    &fs.PathError{Op: "x", Path: marker, Err: syscall.EACCES},
		"LinkError":    &os.LinkError{Op: "x", Old: marker, New: marker, Err: syscall.EACCES},
		"SyscallError": os.NewSyscallError(marker, syscall.EACCES),
	} {
		t.Run(name, func(t *testing.T) {
			err := newOpError("op", wrapped)
			if err.Error() != "quarantine: op failed" || !errors.Is(err, syscall.EACCES) {
				t.Errorf("error = %q", err)
			}
			if errors.As(err, new(*fs.PathError)) || errors.As(err, new(*os.LinkError)) || errors.As(err, new(*os.SyscallError)) {
				t.Error("wrapper leaked through Unwrap")
			}
		})
	}
}

func TestRepairedReturnsCopy(t *testing.T) {
	base := newBase(t)
	openStore(t, base)
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	s := openStore(t, base)
	s.Repaired()[0] = "tampered"
	if got := s.Repaired(); !slices.Equal(got, []string{"base"}) {
		t.Errorf("Repaired = %v after mutating a returned slice", got)
	}
}
