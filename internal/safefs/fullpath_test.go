//go:build darwin || linux

package safefs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// parentLayout builds base/real/file (regular), base/link -> real, and
// base/file, all under a symlink-free base.
func parentLayout(t *testing.T) (base string) {
	t.Helper()
	base = tempDir(t)
	if err := os.Mkdir(filepath.Join(base, "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(base, "real", "file"), []byte(marker))
	writeFile(t, filepath.Join(base, "file"), []byte(marker))
	if err := os.Symlink("real", filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	return base
}

func TestOpenRegularRefusesSymlinkedParent(t *testing.T) {
	base := parentLayout(t)
	// A cloned-repo style link: logs -> dir holding the target file.
	if err := os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "logs")); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"absolute":             filepath.Join(base, "link", "file"),
		"absolute link to abs": filepath.Join(base, "logs", "file"),
		"dotdot after link":    base + "/link/../file",
		"dot component":        base + "/link/./file",
	} {
		t.Run(name, func(t *testing.T) {
			f, err := OpenRegular(path)
			if err == nil {
				_ = f.Close()
			}
			isSymlink(t, err)
		})
	}
}

func TestOpenRegularRefusesSymlinkedGrandparent(t *testing.T) {
	base := parentLayout(t)
	if err := os.Mkdir(filepath.Join(base, "real", "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(base, "real", "sub", "file"), []byte(marker))
	_, err := OpenRegular(filepath.Join(base, "link", "sub", "file"))
	isSymlink(t, err)
}

func TestOpenRegularAcceptsPathsWithoutSymlinks(t *testing.T) {
	base := parentLayout(t)
	for name, path := range map[string]string{
		"plain":        filepath.Join(base, "real", "file"),
		"dot":          base + "/./real/./file",
		"double slash": base + "//real//file",
		"dotdot":       filepath.Join(base, "real") + "/../file",
	} {
		t.Run(name, func(t *testing.T) {
			f, err := OpenRegular(path)
			if err != nil {
				t.Fatalf("OpenRegular(%q): %v", path, err)
			}
			_ = f.Close()
		})
	}
}

func TestOpenRegularRelativePaths(t *testing.T) {
	base := parentLayout(t)

	t.Run("relative file", func(t *testing.T) {
		t.Chdir(base)
		f, err := OpenRegular("real/file")
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	})
	t.Run("relative symlinked parent", func(t *testing.T) {
		t.Chdir(base)
		_, err := OpenRegular("link/file")
		isSymlink(t, err)
	})
	t.Run("relative dotdot after link", func(t *testing.T) {
		t.Chdir(base)
		_, err := OpenRegular("link/../file")
		isSymlink(t, err)
	})
	t.Run("cwd reached through a symlink is not re-checked", func(t *testing.T) {
		t.Chdir(filepath.Join(base, "link"))
		f, err := OpenRegular("file")
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	})
	t.Run("symlink below a symlinked cwd is refused", func(t *testing.T) {
		if err := os.Symlink("..", filepath.Join(base, "real", "up")); err != nil {
			t.Fatal(err)
		}
		t.Chdir(filepath.Join(base, "link"))
		_, err := OpenRegular("up/file")
		isSymlink(t, err)
	})
}

func TestOpenRegularDetectsParentSwappedAfterLstat(t *testing.T) {
	base := tempDir(t)
	parent := filepath.Join(base, "parent")
	elsewhere := filepath.Join(base, "elsewhere")
	for _, d := range []string{parent, elsewhere} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(parent, "file"), []byte(marker))
	writeFile(t, filepath.Join(elsewhere, "file"), []byte(marker))

	setHook(t, func() {
		if err := os.Rename(parent, parent+".old"); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(elsewhere, parent); err != nil {
			t.Error(err)
		}
	})
	f, err := OpenRegular(filepath.Join(parent, "file"))
	if err == nil {
		_ = f.Close()
	}
	if !errors.Is(err, ErrSymlink) {
		t.Fatalf("got %v, want ErrSymlink", err)
	}
}

func TestOpenRegularFullPathLeaksNoDescriptors(t *testing.T) {
	base := parentLayout(t)
	if err := os.Mkdir(filepath.Join(base, "real", "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	paths := []string{
		filepath.Join(base, "link", "file"),             // symlink mid-path
		filepath.Join(base, "real", "sub", "missing"),   // missing leaf
		filepath.Join(base, "real", "nodir", "file"),    // missing middle
		filepath.Join(base, "real", "file", "x"),        // file used as directory
		filepath.Join(base, "real", "sub"),              // directory leaf
		filepath.Join(base, "real") + "/../real/./file", // success
	}
	before := fdCount(t)
	for range 20 {
		for _, p := range paths {
			if f, err := OpenRegular(p); err == nil {
				_ = f.Close()
			}
		}
	}
	if after := fdCount(t); after != before {
		t.Fatalf("descriptors: before %d, after %d", before, after)
	}
}
