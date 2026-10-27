package ingest

import (
	"os"
	"path/filepath"
	"testing"
)

// A root typed as /tmp/... is rewritten by OpenRegular to /private/tmp/...,
// which is where the headroom in MaxPathBytes comes from.
func TestPathCapWithSystemLinkRoot(t *testing.T) {
	real, err := os.MkdirTemp("/private/tmp", "rs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(real) })
	typed := "/tmp/" + filepath.Base(real) + "/"

	pathOfLen(t, real, len(typed), maxPath, false)
	res, werr := walk(t, typed, Limits{}) // walk opens every Path
	if werr != nil || len(res.Artifacts) != 1 || len(res.Artifacts[0].Path) != maxPath {
		t.Fatalf("at the cap: err = %v, artifacts = %d", werr, len(res.Artifacts))
	}

	over, err := os.MkdirTemp("/private/tmp", "rs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(over) })
	typed = "/tmp/" + filepath.Base(over) + "/"
	pathOfLen(t, over, len(typed), maxPath+1, false)
	res, werr = walk(t, typed, Limits{})
	expectIncomplete(t, res, werr, 0, false, 0, 0, 1)
	if len(res.Artifacts) != 0 {
		t.Errorf("over the cap: artifacts = %d", len(res.Artifacts))
	}
}
