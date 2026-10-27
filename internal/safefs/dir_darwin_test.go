package safefs

import (
	"errors"
	"testing"
)

// ADR 0002 decision 3: /tmp/ is rewritten to /private/tmp/ after the system
// link is verified; the bare "/tmp" spelling is not rewritten and is refused.
func TestOpenDirRootMacOSSystemLinks(t *testing.T) {
	f, r, err := OpenDirRoot("/tmp/")
	if err != nil {
		t.Fatalf("OpenDirRoot(/tmp/) error = %v", err)
	}
	closeDirRoot(f, r)

	f, r, err = OpenDirRoot("/tmp")
	closeDirRoot(f, r)
	if !errors.Is(err, ErrSymlink) {
		t.Errorf("OpenDirRoot(/tmp) error = %v, want ErrSymlink", err)
	}
}
