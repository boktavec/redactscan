package safefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSystemPathRule(t *testing.T) {
	always := func(string) bool { return true }
	never := func(string) bool { return false }
	tests := []struct {
		name  string
		path  string
		check func(string) bool
		want  string
	}{
		{"tmp", "/tmp/a", always, "/private/tmp/a"},
		{"var", "/var/folders/x/y", always, "/private/var/folders/x/y"},
		{"etc", "/etc/hosts", always, "/private/etc/hosts"},
		{"check fails", "/tmp/a", never, "/tmp/a"},
		{"similar prefix", "/tmpx/a", always, "/tmpx/a"},
		{"double slash", "//tmp/a", always, "//tmp/a"},
		{"dot component", "/./tmp/a", always, "/./tmp/a"},
		{"already private", "/private/tmp/a", always, "/private/tmp/a"},
		{"bare name", "/tmp", always, "/tmp"},
		{"relative", "tmp/a", always, "tmp/a"},
		{"other root dir", "/usr/a", always, "/usr/a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := systemPath(tt.path, tt.check); got != tt.want {
				t.Fatalf("systemPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestSystemPathChecksOnlyTheMatchingName(t *testing.T) {
	var asked []string
	systemPath("/var/x", func(name string) bool { asked = append(asked, name); return false })
	if len(asked) != 1 || asked[0] != "var" {
		t.Fatalf("check called with %v, want [var]", asked)
	}
}

func TestRealSystemLinksAreTrusted(t *testing.T) {
	for _, name := range systemLinks {
		if !trustedSystemLink(name) {
			t.Errorf("/%s not trusted: not a root-owned link to private/%s on this system", name, name)
		}
	}
}

func TestTrustedLinkRefusesUserLinks(t *testing.T) {
	root := tempDir(t)
	if err := os.Mkdir(filepath.Join(root, "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A user-made link named like a system link, with the exact target.
	if err := os.Symlink("private/tmp", filepath.Join(root, "tmp")); err != nil {
		t.Fatal(err)
	}
	// A link with a different target.
	if err := os.Symlink("/etc", filepath.Join(root, "var")); err != nil {
		t.Fatal(err)
	}
	// A regular directory.
	if err := os.Mkdir(filepath.Join(root, "etc"), 0o700); err != nil {
		t.Fatal(err)
	}

	if isTrustedLink(root, "tmp", 0) && os.Getuid() != 0 {
		t.Error("user-owned link trusted as root-owned")
	}
	if !isTrustedLink(root, "tmp", uint32(os.Getuid())) {
		t.Error("control failed: matching owner and target should be trusted")
	}
	if isTrustedLink(root, "var", uint32(os.Getuid())) {
		t.Error("link with a different target trusted")
	}
	if isTrustedLink(root, "etc", uint32(os.Getuid())) {
		t.Error("directory trusted as a link")
	}
	if isTrustedLink(root, "missing", uint32(os.Getuid())) {
		t.Error("missing entry trusted")
	}
}

func TestOpenRegularThroughSystemLinks(t *testing.T) {
	t.Run("raw TempDir under /var/folders", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file") // deliberately not EvalSymlinks
		writeFile(t, path, []byte(marker))
		f, err := OpenRegular(path)
		if err != nil {
			t.Fatalf("OpenRegular(%q): %v", path, err)
		}
		_ = f.Close()
	})
	t.Run("/tmp", func(t *testing.T) {
		dir, err := os.MkdirTemp("/tmp", "safefs-test-")
		if err != nil {
			t.Skipf("cannot create under /tmp: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		path := filepath.Join(dir, "file")
		writeFile(t, path, []byte(marker))
		f, err := OpenRegular(path)
		if err != nil {
			t.Fatalf("OpenRegular(%q): %v", path, err)
		}
		_ = f.Close()
	})
	t.Run("user symlink beneath /tmp is still refused", func(t *testing.T) {
		dir, err := os.MkdirTemp("/tmp", "safefs-test-")
		if err != nil {
			t.Skipf("cannot create under /tmp: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		if err := os.Mkdir(filepath.Join(dir, "real"), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, "real", "file"), []byte(marker))
		if err := os.Symlink("real", filepath.Join(dir, "link")); err != nil {
			t.Fatal(err)
		}
		_, err = OpenRegular(filepath.Join(dir, "link", "file"))
		isSymlink(t, err)
	})
}
