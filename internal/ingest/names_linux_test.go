package ingest

import (
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

// Hostile names are data: they must produce Artifacts and Findings, never
// ErrInternal. (macOS rejects invalid UTF-8 names, so this runs on Linux only.)
func TestHostileNamesAreListed(t *testing.T) {
	root := tempRoot(t)
	names := []string{
		"bad-utf8-\xff\xfe",
		"ansi-\x1b[31mred",
		"bidi-‮txt.exe",
		"line\nbreak",
		"ctl-\x01",
	}
	for _, n := range names {
		mkfile(t, filepath.Join(root, n))
	}
	mksymlink(t, "x", filepath.Join(root, "link-\xff"))

	res, err := walk(t, root, Limits{}) // walk opens every Path
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(res.Artifacts) != len(names) || len(findingsOf(res, "ingest-symlink")) != 1 {
		t.Fatalf("artifacts = %d, findings = %+v", len(res.Artifacts), res.Findings)
	}
	var got []string
	for _, a := range res.Artifacts {
		got = append(got, a.Name)
	}
	if want := slices.Sorted(slices.Values(names)); !reflect.DeepEqual(got, want) {
		t.Errorf("names = %q, want %q", got, want)
	}
}
