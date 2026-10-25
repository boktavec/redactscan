package safefs

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// S1 (macOS), background only: WriteSibling creates through Root.OpenFile, not
// this call. O_CREAT|O_EXCL|O_NOFOLLOW_ANY at a symlinked name gives EEXIST,
// and a symlinked parent gives ELOOP.
func TestNofollowAnyExclusiveCreate(t *testing.T) {
	dir := tempDir(t)
	target := filepath.Join(dir, "target")
	writeFile(t, target, []byte("target"))
	if err := os.Symlink(target, filepath.Join(dir, "planted")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, filepath.Join(dir, "parent")); err != nil {
		t.Fatal(err)
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL | oNofollowAny

	_, err := os.OpenFile(filepath.Join(dir, "planted"), flags, 0o600)
	if !errors.Is(err, syscall.EEXIST) {
		t.Errorf("symlink at name: %v, want EEXIST", err)
	}
	_, err = os.OpenFile(filepath.Join(dir, "parent", "new"), flags, 0o600)
	if !errors.Is(err, syscall.ELOOP) {
		t.Errorf("symlinked parent: %v, want ELOOP", err)
	}
	if got := readString(t, target); got != "target" {
		t.Errorf("target changed to %q", got)
	}
}
