package quarantine

import (
	"path/filepath"
	"testing"
)

func TestOpenCreatesNoIndexMarker(t *testing.T) {
	base := newBase(t)
	openStore(t, base)
	if got := mode(t, filepath.Join(base, ".metadata_never_index")); got != 0o600 {
		t.Errorf("marker mode = %v, want 0600", got)
	}
	openStore(t, base) // an existing marker does not fail Open
}
