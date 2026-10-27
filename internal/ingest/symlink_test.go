//go:build darwin || linux

package ingest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/boktavec/redactscan/internal/finding"
)

func TestSymlinkClassification(t *testing.T) {
	base := tempRoot(t)
	root := filepath.Join(base, "tree")
	mkfile(t, filepath.Join(root, "a", "d", "in.txt"))
	mkdir(t, filepath.Join(root, "a", "b"))
	mkfile(t, filepath.Join(base, "outside", "secret.txt"))
	// A symlink whose resolution needs a directory without search permission.
	mkfile(t, filepath.Join(root, "locked", "inner"))
	if err := os.Chmod(filepath.Join(root, "locked"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "locked"), 0o700) })

	links := map[string]string{
		"a/b/sibling":   "../d",                                       // nested sibling, in-root
		"a/b/up":        "../../../outside",                           // ../../.. escape
		"abs":           filepath.Join(base, "outside", "secret.txt"), // absolute escape
		"abs-missing":   filepath.Join(base, "no-such-"+marker),       // escape wins over missing
		"dangling":      "no-such-" + marker,
		"self":          "self",
		"loop-a":        "loop-b",
		"loop-b":        "loop-a",
		"to-locked":     "locked/inner",
		"in-root-file":  "a/d/in.txt",
		"dangling-deep": "a/d/no-such-" + marker,
	}
	for rel, target := range links {
		mksymlink(t, target, filepath.Join(root, filepath.FromSlash(rel)))
	}
	emptyTarget := os.Symlink("", filepath.Join(root, "empty")) == nil // macOS only

	want := map[string]struct {
		kind linkKind
		sev  finding.Severity
	}{
		"a/b/sibling":   {linkInRoot, finding.SeverityInfo},
		"a/b/up":        {linkEscape, finding.SeverityMedium},
		"abs":           {linkEscape, finding.SeverityMedium},
		"abs-missing":   {linkEscape, finding.SeverityMedium},
		"dangling":      {linkDangling, finding.SeverityInfo},
		"dangling-deep": {linkDangling, finding.SeverityInfo},
		"self":          {linkLoop, finding.SeverityLow},
		"loop-a":        {linkLoop, finding.SeverityLow},
		"loop-b":        {linkLoop, finding.SeverityLow},
		"in-root-file":  {linkInRoot, finding.SeverityInfo},
	}
	if emptyTarget {
		want["empty"] = struct {
			kind linkKind
			sev  finding.Severity
		}{linkEscape, finding.SeverityMedium}
	}
	if os.Geteuid() != 0 { // root ignores directory permissions
		want["to-locked"] = struct {
			kind linkKind
			sev  finding.Severity
		}{linkUnknown, finding.SeverityMedium}
	}

	// The unreadable directory makes the walk incomplete; that is expected.
	res, _ := walk(t, root, Limits{})
	got := map[string]finding.Finding{}
	for _, f := range findingsOf(res, "ingest-symlink") {
		got[f.File] = f
		if f.Category != "ingest" || f.Title != "symlink not followed" {
			t.Errorf("%s: category %q, title %q", f.File, f.Category, f.Title)
		}
		if blob := fmt.Sprint(f); strings.Contains(blob, marker) || strings.Contains(blob, "outside") {
			t.Errorf("%s: finding leaks a link target: %v", f.File, f)
		}
	}
	for rel, w := range want {
		f, ok := got[rel]
		if !ok {
			t.Errorf("%s: no symlink finding", rel)
			continue
		}
		if f.Metadata["link_kind"] != string(w.kind) || f.Severity != w.sev {
			t.Errorf("%s: kind %v severity %v, want %v %v", rel, f.Metadata["link_kind"], f.Severity, w.kind, w.sev)
		}
		if _, hasErrno := f.Metadata["errno"]; hasErrno != (w.kind == linkUnknown) {
			t.Errorf("%s: errno presence %v for kind %v", rel, hasErrno, w.kind)
		}
	}
	if f, ok := got["to-locked"]; ok && f.Metadata["link_kind"] == string(linkUnknown) && f.Metadata["errno"] != int(syscall.EACCES) {
		t.Errorf("to-locked: errno = %v, want EACCES", f.Metadata["errno"])
	}
	for rel := range got {
		if _, ok := want[rel]; !ok && rel != "to-locked" && rel != "empty" {
			t.Errorf("unexpected symlink finding for %s", rel)
		}
	}
	for _, a := range res.Artifacts {
		if strings.Contains(a.RelativePath, "sibling") || strings.HasPrefix(a.RelativePath, "abs") {
			t.Errorf("artifact %s listed through a symlink", a.RelativePath)
		}
	}
}

// A link inside a nested directory must be classified against the whole tree.
// Against its own directory's root, the in-root sibling would look like an
// escape.
func TestNestedSiblingLinkIsNotAnEscape(t *testing.T) {
	root := tempRoot(t)
	mkfile(t, filepath.Join(root, "a", "d", "in.txt"))
	mkdir(t, filepath.Join(root, "a", "b"))
	mksymlink(t, "../d", filepath.Join(root, "a", "b", "c"))
	res, err := walk(t, root, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	fs := findingsOf(res, "ingest-symlink")
	if len(fs) != 1 || fs[0].Metadata["link_kind"] != string(linkInRoot) {
		t.Errorf("findings = %+v, want one in-root link", fs)
	}
}

// chain makes links name1 -> name2 -> ... -> nameN -> target and returns the
// first link's name.
func chain(t *testing.T, root, prefix string, n int, target string) string {
	t.Helper()
	for i := 1; i <= n; i++ {
		to := target
		if i < n {
			to = fmt.Sprintf("%s%d", prefix, i+1)
		}
		mksymlink(t, to, filepath.Join(root, fmt.Sprintf("%s%d", prefix, i)))
	}
	return prefix + "1"
}

func TestSymlinkChainsAndIntermediates(t *testing.T) {
	root := tempRoot(t)
	mkfile(t, filepath.Join(root, "file"))
	mkfifo(t, filepath.Join(root, "fifo"))
	mksymlink(t, "fifo", filepath.Join(root, "to-fifo"))
	mksymlink(t, "fifo/x", filepath.Join(root, "through-fifo"))
	chain(t, root, "c8-", 8, "file")
	chain(t, root, "c9-", 9, "file")

	res, err := walk(t, root, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]finding.Finding{}
	for _, f := range findingsOf(res, "ingest-symlink") {
		got[f.File] = f
	}
	cases := []struct {
		rel   string
		kind  linkKind
		errno any // nil when absent
	}{
		{"c8-1", linkInRoot, nil},
		{"c9-1", linkLoop, nil}, // a chain over the link limit reads as ELOOP
		{"to-fifo", linkInRoot, nil},
		{"through-fifo", linkUnknown, int(syscall.ENOTDIR)},
	}
	for _, c := range cases {
		f, ok := got[c.rel]
		if !ok {
			t.Errorf("%s: no finding", c.rel)
			continue
		}
		if f.Metadata["link_kind"] != string(c.kind) || f.Metadata["errno"] != c.errno {
			t.Errorf("%s: metadata %v, want kind %s errno %v", c.rel, f.Metadata, c.kind, c.errno)
		}
	}
}
