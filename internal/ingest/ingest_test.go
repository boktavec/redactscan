//go:build darwin || linux

package ingest

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/safefs"
)

func TestWalkRegularFiles(t *testing.T) {
	root := tempRoot(t)
	mkfile(t, filepath.Join(root, "B.txt"))
	mkfile(t, filepath.Join(root, "a.txt"))
	mkfile(t, filepath.Join(root, "sub", "deeper", "c.txt"))
	mkdir(t, filepath.Join(root, "empty"))

	// A trailing slash on the root must not double up in Path.
	res, err := walk(t, root+"/", Limits{})
	if err != nil || len(res.Findings) != 0 {
		t.Fatalf("err = %v, findings = %d, want clean", err, len(res.Findings))
	}
	// Byte order: "B.txt" < "a.txt" < "sub".
	want := []string{"B.txt", "a.txt", "sub/deeper/c.txt"}
	if got := relPaths(res); !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	for i, a := range res.Artifacts {
		wantA := artifact.Artifact{
			ID:           "a-" + string(rune('1'+i)),
			Path:         root + "/" + want[i],
			RelativePath: want[i],
			Name:         filepath.Base(want[i]),
			Size:         1,
			Source:       artifact.SourceMetadata{Type: artifact.SourceDirectory},
		}
		if !reflect.DeepEqual(a, wantA) {
			t.Errorf("artifact %d = %+v, want %+v", i, a, wantA)
		}
		f, err := safefs.OpenRegular(a.Path)
		if err != nil {
			t.Errorf("OpenRegular(%s): %v", a.ID, err)
			continue
		}
		_ = f.Close()
	}
}

func TestWalkIsDeterministic(t *testing.T) {
	root := tempRoot(t)
	for i := range 300 {
		mkfile(t, filepath.Join(root, fmt.Sprintf("d%d", i%5), fmt.Sprintf("f%03d", i)))
	}
	first, err1 := walk(t, root, Limits{})
	second, err2 := walk(t, root, Limits{})
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if !reflect.DeepEqual(first, second) || len(first.Artifacts) == 0 {
		t.Error("two walks of the same tree differ")
	}
}

func TestWalkListsAcrossBatches(t *testing.T) {
	root := tempRoot(t)
	for i := range listBatch + 50 {
		mkfile(t, filepath.Join(root, fmt.Sprintf("f%05d", i)))
	}
	res, err := walk(t, root, Limits{})
	if err != nil || len(res.Artifacts) != listBatch+50 {
		t.Fatalf("err = %v, artifacts = %d, want %d", err, len(res.Artifacts), listBatch+50)
	}
}

func TestWalkRejectsInvalidRootBeforeIO(t *testing.T) {
	swapReadNames(t, func(*os.File, int) ([]string, error) {
		t.Error("listing ran for an invalid root")
		return nil, nil
	})
	for _, root := range []string{"", "a\x00b"} {
		res, err := walk(t, root, Limits{})
		if !errors.Is(err, ErrInvalidRoot) || len(res.Artifacts)+len(res.Findings) != 0 {
			t.Errorf("Walk(%q) = %v, %v", root, res, err)
		}
	}
}

func TestWalkFatalRootErrors(t *testing.T) {
	base := tempRoot(t)
	mkfile(t, filepath.Join(base, "file"))
	mkfifo(t, filepath.Join(base, "fifo"))
	mkdir(t, filepath.Join(base, "real", "sub"))
	mksymlink(t, filepath.Join(base, "real"), filepath.Join(base, "link"))
	cases := []struct {
		name, root string
		want       error
	}{
		{"regular file", filepath.Join(base, "file"), safefs.ErrNotDir},
		{"fifo", filepath.Join(base, "fifo"), safefs.ErrNotDir},
		{"symlink root", filepath.Join(base, "link"), safefs.ErrSymlink},
		{"symlink parent", filepath.Join(base, "link", "sub"), safefs.ErrSymlink},
		{"marker name", filepath.Join(base, marker), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := walk(t, tc.root, Limits{})
			if err == nil || errors.Is(err, ErrIncomplete) || len(res.Artifacts)+len(res.Findings) != 0 {
				t.Fatalf("Walk = %v, %v; want a fatal error and an empty result", res, err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestWalkSlashRoot(t *testing.T) {
	res, err := walk(t, "/", Limits{MaxDepth: 1, MaxEntries: 20})
	if err != nil && !errors.Is(err, ErrIncomplete) {
		t.Fatal(err)
	}
	for _, a := range res.Artifacts {
		if !strings.HasPrefix(a.Path, "/") || strings.HasPrefix(a.Path, "//") {
			t.Errorf("Path = %q", a.Path)
		}
	}
}

func TestWalkInvalidLimits(t *testing.T) {
	swapReadNames(t, func(*os.File, int) ([]string, error) {
		t.Error("listing ran for invalid limits")
		return nil, nil
	})
	root := tempRoot(t)
	for _, lim := range []Limits{
		{MaxDepth: -1}, {MaxEntries: -1}, {MaxDepth: MaxMaxDepth + 1}, {MaxEntries: MaxMaxEntries + 1},
	} {
		if res, err := walk(t, root, lim); !errors.Is(err, ErrInvalidLimits) || len(res.Findings) != 0 {
			t.Errorf("Walk(%+v) = %v, %v", lim, res, err)
		}
	}
}

func TestLimitsResolve(t *testing.T) {
	for _, tc := range []struct {
		lim            Limits
		depth, entries int
	}{
		{Limits{}, DefaultMaxDepth, DefaultMaxEntries},
		{Limits{MaxDepth: 3, MaxEntries: 7}, 3, 7},
		{Limits{MaxDepth: MaxMaxDepth, MaxEntries: MaxMaxEntries}, MaxMaxDepth, MaxMaxEntries},
	} {
		d, e, err := tc.lim.resolve()
		if err != nil || d != tc.depth || e != tc.entries {
			t.Errorf("resolve(%+v) = %d, %d, %v", tc.lim, d, e, err)
		}
	}
}

func TestSymlinksAreReportedNotFollowed(t *testing.T) {
	base := tempRoot(t)
	outside := filepath.Join(base, "outside")
	mkfile(t, filepath.Join(outside, "secret.txt"))
	root := filepath.Join(base, "tree")
	mkfile(t, filepath.Join(root, "real", "in.txt"))
	mksymlink(t, outside, filepath.Join(root, "escape"))
	mksymlink(t, "loop", filepath.Join(root, "loop"))
	mksymlink(t, "real", filepath.Join(root, "inroot"))
	mksymlink(t, "no-such-"+marker, filepath.Join(root, "dangling"))
	mksymlink(t, filepath.Join(outside, "secret.txt"), filepath.Join(root, "file-link"))

	res, err := walk(t, root, Limits{})
	if err != nil {
		t.Fatalf("symlinks alone must not make the walk incomplete: %v", err)
	}
	if got := relPaths(res); !reflect.DeepEqual(got, []string{"real/in.txt"}) {
		t.Errorf("artifacts = %v, nothing under or through a link may be listed", got)
	}
	var files []string
	for _, f := range findingsOf(res, "ingest-symlink") {
		files = append(files, f.File)
		if _, ok := f.Metadata["link_kind"]; !ok {
			t.Errorf("%s: no link_kind in %v", f.File, f.Metadata)
		}
	}
	if want := []string{"dangling", "escape", "file-link", "inroot", "loop"}; !reflect.DeepEqual(files, want) {
		t.Errorf("symlink findings for %v, want %v", files, want)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Title+f.Description+f.File+f.ID, "no-such") || strings.Contains(f.Description, outside) {
			t.Errorf("finding %s leaks a link target", f.ID)
		}
	}
}

func TestSpecialFilesAreSkipped(t *testing.T) {
	root := tempRoot(t)
	mkfifo(t, filepath.Join(root, "pipe"))
	mkfile(t, filepath.Join(root, "ok.txt"))

	res, err := walk(t, root, Limits{})
	if err != nil {
		t.Fatalf("special files alone must not make the walk incomplete: %v", err)
	}
	special := findingsOf(res, "ingest-special-file")
	if len(special) != 1 || special[0].File != "pipe" || special[0].Severity != finding.SeverityLow ||
		special[0].Metadata["file_type"] != "fifo" {
		t.Errorf("findings = %+v", res.Findings)
	}
	if got := relPaths(res); !reflect.DeepEqual(got, []string{"ok.txt"}) {
		t.Errorf("artifacts = %v", got)
	}
}

func TestSocketAndDeviceFileTypes(t *testing.T) {
	// A socket path must fit sun_path (104 bytes), so use a short base.
	base, err := os.MkdirTemp("/tmp", "rs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if base, err = filepath.EvalSymlinks(base); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", filepath.Join(base, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	res, werr := walk(t, base, Limits{})
	if werr != nil {
		t.Fatal(werr)
	}
	if f := findingsOf(res, "ingest-special-file"); len(f) != 1 || f[0].Metadata["file_type"] != "socket" {
		t.Errorf("socket findings = %+v", res.Findings)
	}

	// /dev exists on every supported OS and holds character devices.
	res, werr = walk(t, "/dev", Limits{MaxDepth: 1, MaxEntries: 5000})
	if werr != nil && !errors.Is(werr, ErrIncomplete) {
		t.Fatal(werr)
	}
	var devices int
	for _, f := range findingsOf(res, "ingest-special-file") {
		if f.Metadata["file_type"] == "device" {
			devices++
		}
	}
	if devices == 0 {
		t.Error("no device finding under /dev")
	}
}

func expectIncomplete(t *testing.T, res Result, err error, depth int, capped bool, readErrors, changed, tooLong int) {
	t.Helper()
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err = %v, want ErrIncomplete", err)
	}
	inc := findingsOf(res, "ingest-incomplete")
	if len(inc) != 1 || res.Findings[len(res.Findings)-1].ID != inc[0].ID || inc[0].Severity != finding.SeverityMedium || inc[0].File != "" {
		t.Fatalf("want exactly one medium ingest-incomplete finding, last; got %+v", res.Findings)
	}
	want := map[string]any{
		"depth_skipped": depth, "entries_capped": capped, "read_errors": readErrors, "changed": changed, "path_too_long": tooLong,
	}
	if !reflect.DeepEqual(inc[0].Metadata, want) {
		t.Errorf("counters = %v, want %v", inc[0].Metadata, want)
	}
}

func TestDepthLimit(t *testing.T) {
	root := tempRoot(t)
	mkfile(t, filepath.Join(root, "f"))
	mkfile(t, filepath.Join(root, "d1", "f"))
	mkfile(t, filepath.Join(root, "d1", "d2", "f"))
	mkfile(t, filepath.Join(root, "d1", "d2", "d3", "f"))
	mkfile(t, filepath.Join(root, "z"))

	// d3 has depth 3 == MaxDepth: counted, never opened. Siblings continue.
	res, err := walk(t, root, Limits{MaxDepth: 3})
	expectIncomplete(t, res, err, 1, false, 0, 0, 0)
	if got, want := relPaths(res), []string{"d1/d2/f", "d1/f", "f", "z"}; !reflect.DeepEqual(got, want) {
		t.Errorf("artifacts = %v, want %v", got, want)
	}
	if res, err = walk(t, root, Limits{MaxDepth: 4}); err != nil || len(res.Artifacts) != 5 {
		t.Errorf("MaxDepth 4: err = %v, artifacts = %d, want 5 and clean", err, len(res.Artifacts))
	}
}

func TestEntryLimit(t *testing.T) {
	t.Run("cut inside one directory", func(t *testing.T) {
		root := tempRoot(t)
		for _, n := range []string{"a", "b", "c", "d", "e", "f"} {
			mkfile(t, filepath.Join(root, n))
		}
		res, err := walk(t, root, Limits{MaxEntries: 4})
		expectIncomplete(t, res, err, 0, true, 0, 0, 0)
		if len(res.Artifacts) != 4 {
			t.Errorf("artifacts = %d, want 4", len(res.Artifacts))
		}
	})
	t.Run("across directories", func(t *testing.T) {
		root := tempRoot(t)
		mkfile(t, filepath.Join(root, "a", "1"))
		mkfile(t, filepath.Join(root, "a", "2"))
		mkfile(t, filepath.Join(root, "b", "1"))
		mkfile(t, filepath.Join(root, "b", "2"))
		// root: a, b (2); a: 1, 2 (4); b is not listed any more.
		res, err := walk(t, root, Limits{MaxEntries: 4})
		expectIncomplete(t, res, err, 0, true, 0, 0, 0)
		if got := relPaths(res); !reflect.DeepEqual(got, []string{"a/1", "a/2"}) {
			t.Errorf("artifacts = %v", got)
		}
	})
	t.Run("exactly the limit is complete", func(t *testing.T) {
		root := tempRoot(t)
		for _, n := range []string{"a", "b", "c"} {
			mkfile(t, filepath.Join(root, n))
		}
		if res, err := walk(t, root, Limits{MaxEntries: 3}); err != nil || len(res.Artifacts) != 3 {
			t.Errorf("err = %v, artifacts = %d", err, len(res.Artifacts))
		}
	})
}

func TestEntryLimitCountsEveryKind(t *testing.T) {
	root := tempRoot(t)
	for _, n := range []string{"a", "b", "c", "d"} {
		mkfifo(t, filepath.Join(root, n))
	}
	res, err := walk(t, root, Limits{MaxEntries: 2})
	expectIncomplete(t, res, err, 0, true, 0, 0, 0)
	if got := len(findingsOf(res, "ingest-special-file")); got != 2 {
		t.Errorf("special findings = %d, want 2", got)
	}
}

func TestPathLengthCap(t *testing.T) {
	t.Run("at the cap", func(t *testing.T) {
		root := tempRoot(t)
		pathOfLen(t, root, len(root)+1, maxPath, false)
		res, err := walk(t, root, Limits{}) // walk opens every Path
		if err != nil || len(res.Artifacts) != 1 || len(res.Artifacts[0].Path) != maxPath {
			t.Fatalf("err = %v, artifacts = %d, want one Artifact of %d bytes", err, len(res.Artifacts), maxPath)
		}
	})
	t.Run("over the cap", func(t *testing.T) {
		root := tempRoot(t)
		pathOfLen(t, root, len(root)+1, maxPath+1, false)
		mkfile(t, filepath.Join(root, "ok"))
		res, err := walk(t, root, Limits{})
		expectIncomplete(t, res, err, 0, false, 0, 0, 1)
		long := findingsOf(res, "ingest-path-too-long")
		if len(long) != 1 || long[0].Severity != finding.SeverityMedium || len(res.Artifacts) != 1 || res.Artifacts[0].Name != "ok" {
			t.Errorf("findings = %+v, artifacts = %d", res.Findings, len(res.Artifacts))
		}
	})
	t.Run("directory over the cap is not descended", func(t *testing.T) {
		root := tempRoot(t)
		pathOfLen(t, root, len(root)+1, maxPath+1, true)
		res, err := walk(t, root, Limits{})
		expectIncomplete(t, res, err, 0, false, 0, 0, 1)
		if len(res.Artifacts) != 0 {
			t.Errorf("artifacts = %d", len(res.Artifacts))
		}
	})
}

func TestChangedDirectories(t *testing.T) {
	swaps := map[string]func(t *testing.T, path string){
		"fifo": func(t *testing.T, p string) { mkfifo(t, p) },
		"symlink to fifo": func(t *testing.T, p string) {
			mkfifo(t, p+".fifo")
			mksymlink(t, p+".fifo", p)
		},
		"symlink to directory": func(t *testing.T, p string) {
			mkdir(t, p+".other")
			mksymlink(t, p+".other", p)
		},
		"different directory": func(t *testing.T, p string) {
			if err := os.Rename(p+".new", p); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, swap := range swaps {
		t.Run(name, func(t *testing.T) {
			root := tempRoot(t)
			victim := filepath.Join(root, "victim")
			mkfile(t, filepath.Join(victim, "inside"))
			swapHook(t, func(n string) {
				if n != "victim" {
					return
				}
				// Created while the original still exists, so the inode differs.
				mkdir(t, victim+".new")
				if err := os.RemoveAll(victim); err != nil {
					t.Error(err)
				}
				swap(t, victim)
			})
			res, err := walk(t, root, Limits{})
			expectIncomplete(t, res, err, 0, false, 0, 1, 0)
			if f := findingsOf(res, "ingest-changed"); len(f) != 1 || f[0].File != "victim" || f[0].Severity != finding.SeverityMedium {
				t.Errorf("findings = %+v", res.Findings)
			}
			if len(res.Artifacts) != 0 {
				t.Errorf("artifacts = %v, nothing behind a swapped directory may be listed", relPaths(res))
			}
		})
	}
}

func TestUnreadableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	root := tempRoot(t)
	mkfile(t, filepath.Join(root, "locked", "f"))
	mkfile(t, filepath.Join(root, "z"))
	if err := os.Chmod(filepath.Join(root, "locked"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "locked"), 0o700) })

	res, err := walk(t, root, Limits{})
	expectIncomplete(t, res, err, 0, false, 1, 0, 0)
	rd := findingsOf(res, "ingest-read-error")
	if len(rd) != 1 || rd[0].File != "locked" || rd[0].Severity != finding.SeverityMedium || rd[0].Metadata["op"] != "open dir" {
		t.Errorf("findings = %+v", res.Findings)
	}
	if got := relPaths(res); !reflect.DeepEqual(got, []string{"z"}) {
		t.Errorf("artifacts = %v, the walk must continue with siblings", got)
	}
}

func TestListErrorKeepsNamesAlreadyRead(t *testing.T) {
	root := tempRoot(t)
	mkfile(t, filepath.Join(root, "a"))
	mkfile(t, filepath.Join(root, "b"))
	swapReadNames(t, func(d *os.File, max int) ([]string, error) {
		names, err := listNames(d, max)
		return append(names, "ghost-"+marker), errors.Join(err, errors.New(marker))
	})
	res, err := walk(t, root, Limits{})
	expectIncomplete(t, res, err, 0, false, 2, 0, 0)
	// The list error comes first, then the lstat failure of the vanished name.
	rd := findingsOf(res, "ingest-read-error")
	if len(rd) != 2 || rd[0].Metadata["op"] != "list dir" || rd[0].Severity != finding.SeverityMedium ||
		rd[1].Metadata["op"] != "lstat" || rd[1].Severity != finding.SeverityLow {
		t.Errorf("read-error findings = %+v", rd)
	}
	if got := relPaths(res); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("artifacts = %v, names read before the error must be processed", got)
	}
}

func TestCleanWalkHasNoIncompleteFinding(t *testing.T) {
	root := tempRoot(t)
	mkfile(t, filepath.Join(root, "a", "f"))
	mkfifo(t, filepath.Join(root, "pipe"))
	mksymlink(t, "/", filepath.Join(root, "link"))
	res, err := walk(t, root, Limits{})
	if err != nil || len(findingsOf(res, "ingest-incomplete")) != 0 {
		t.Errorf("err = %v, findings = %+v", err, res.Findings)
	}
	if len(res.Findings) != 2 {
		t.Errorf("findings = %+v, want symlink and special file only", res.Findings)
	}
}

func TestInvalidProducedValuesAreFatal(t *testing.T) {
	w := &walker{}
	w.addFinding(kindSymlink, finding.SeverityInvalid, "x", nil)
	if w.err != ErrInternal || len(w.res.Findings) != 0 {
		t.Errorf("finding: err = %v, findings = %d", w.err, len(w.res.Findings))
	}
	w = &walker{}
	w.addFinding(kindSymlink, finding.SeverityLow, "x", map[string]any{"k": []string{"unsupported"}})
	if w.err != ErrInternal || len(w.res.Findings) != 0 {
		t.Errorf("finding metadata: err = %v, findings = %d", w.err, len(w.res.Findings))
	}
	w = &walker{}
	w.addArtifact(artifact.Artifact{ID: "a-1", Metadata: map[string]any{"k": []string{"unsupported"}}})
	if w.err != ErrInternal || len(w.res.Artifacts) != 0 {
		t.Errorf("artifact: err = %v, artifacts = %d", w.err, len(w.res.Artifacts))
	}
}

func TestFatalErrorDiscardsPartialResult(t *testing.T) {
	w := &walker{err: ErrInternal, res: Result{Artifacts: []artifact.Artifact{{ID: "a-1"}}}}
	w.c.readErrors = 1 // even an incomplete walk must not return ErrIncomplete
	res, err := w.result()
	if err != ErrInternal || len(res.Artifacts)+len(res.Findings) != 0 {
		t.Errorf("result() = %+v, %v; want an empty Result and ErrInternal", res, err)
	}
}

func TestOpenDescriptorsStayWithinDepthPlusTwo(t *testing.T) {
	root := tempRoot(t)
	mkfile(t, filepath.Join(root, "a", "b", "c", "d", "e", "f"))
	base := fdCount(t)
	calls := 0
	swapHook(t, func(string) {
		if got, limit := fdCount(t), base+calls+2; got > limit {
			t.Errorf("opening level %d: %d descriptors, limit %d", calls+1, got, limit)
		}
		calls++
	})
	if _, err := walk(t, root, Limits{}); err != nil || calls != 5 {
		t.Errorf("err = %v, hook calls = %d, want 5", err, calls)
	}
}
