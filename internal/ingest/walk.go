package ingest

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/safefs"
)

const (
	listBatch = 1024
	// systemLinkHeadroom is the extra length OpenRegular may add when it
	// rewrites a /tmp, /var or /etc root to /private/...
	systemLinkHeadroom = "/private"
)

// Test seams: production never changes them.
var (
	beforeChildOpen = func(name string) {}
	// readNames lists up to max names from an open directory.
	readNames = listNames
)

// kind is the fixed text of one Finding kind.
type kind struct{ id, title, desc string }

var (
	kindSymlink     = kind{"ingest-symlink", "symlink not followed", "A symlink was found and not followed."}
	kindSpecial     = kind{"ingest-special-file", "special file skipped", "A non-regular file was found and not opened."}
	kindReadError   = kind{"ingest-read-error", "read error", "A directory entry could not be read; the scan is incomplete."}
	kindChanged     = kind{"ingest-changed", "directory changed during walk", "A directory changed while it was being opened; the scan is incomplete."}
	kindPathTooLong = kind{"ingest-path-too-long", "path too long", "An entry path exceeds the length limit and was skipped; the scan is incomplete."}
	kindIncomplete  = kind{"ingest-incomplete", "scan incomplete", "Some entries were not scanned; do not treat this result as clean."}
)

type counters struct {
	depthSkipped, readErrors, changed, pathTooLong int
	entriesCapped                                  bool
}

func (c counters) incomplete() bool {
	return c.depthSkipped+c.readErrors+c.changed+c.pathTooLong > 0 || c.entriesCapped
}

type walker struct {
	prefix     string // root with a trailing slash; relative paths are appended
	maxDepth   int
	maxEntries int
	entries    int
	c          counters
	findings   int // sequence number
	res        Result
	err        error // first fatal error; the walk stops once set
}

// walkDir lists dir (closing it) and handles each entry in byte order. r is
// pinned to dir, depth is dir's depth (root = 0) and dirPath is its Path with
// a trailing slash (the prefix for the root).
func (w *walker) walkDir(dir *os.File, r *os.Root, dirPath string, depth int) {
	remaining := w.maxEntries - w.entries
	names, err := readNames(dir, remaining+1)
	_ = dir.Close() // at most one listing handle is open at a time
	if err != nil {
		w.c.readErrors++
		rel := strings.TrimSuffix(dirPath[len(w.prefix):], "/")
		w.addFinding(kindReadError, finding.SeverityMedium, rel, map[string]any{"op": "list dir"})
	}
	slices.Sort(names)
	if len(names) > remaining {
		names = names[:remaining]
		w.c.entriesCapped = true
	}
	w.entries += len(names)

	for _, name := range names {
		if w.err != nil {
			return
		}
		w.entry(r, name, dirPath+name, depth+1)
	}
}

// entry handles one name. Path is the only allocation per entry: the relative
// path and the name are substrings of it.
func (w *walker) entry(r *os.Root, name, path string, depth int) {
	rel := path[len(w.prefix):]
	if len(path)+len(systemLinkHeadroom) >= MaxPathBytes {
		w.c.pathTooLong++
		w.addFinding(kindPathTooLong, finding.SeverityMedium, rel, nil)
		return
	}
	fi, err := r.Lstat(name)
	if err != nil {
		w.c.readErrors++
		w.addFinding(kindReadError, finding.SeverityLow, rel, map[string]any{"op": "lstat"})
		return
	}
	switch mode := fi.Mode().Type(); mode {
	case 0:
		w.addArtifact(artifact.Artifact{
			ID:           "a-" + strconv.Itoa(len(w.res.Artifacts)+1),
			Path:         path,
			RelativePath: rel,
			Name:         path[len(path)-len(name):],
			Size:         fi.Size(),
			Source:       artifact.SourceMetadata{Type: artifact.SourceDirectory},
		})
	case fs.ModeSymlink:
		// Never opened or listed. PR 3 classifies it; until then fail closed.
		w.addFinding(kindSymlink, finding.SeverityMedium, rel, nil)
	case fs.ModeDir:
		w.descend(r, name, path, rel, depth, fi)
	default:
		w.addFinding(kindSpecial, finding.SeverityLow, rel, map[string]any{"file_type": string(safefs.TypeOf(mode))})
	}
}

func (w *walker) descend(r *os.Root, name, path, rel string, depth int, fi fs.FileInfo) {
	if depth >= w.maxDepth {
		w.c.depthSkipped++
		return
	}
	if w.c.entriesCapped {
		return
	}
	beforeChildOpen(name)
	cf, cr, err := safefs.OpenChildDir(r, name, fi)
	switch {
	case errors.Is(err, safefs.ErrChanged):
		w.c.changed++
		w.addFinding(kindChanged, finding.SeverityMedium, rel, nil)
	case err != nil:
		w.c.readErrors++
		w.addFinding(kindReadError, finding.SeverityMedium, rel, map[string]any{"op": "open dir"})
	default:
		w.walkDir(cf, cr, path+"/", depth)
		_ = cr.Close()
	}
}

// addArtifact appends a, or makes the walk fail if it does not validate.
func (w *walker) addArtifact(a artifact.Artifact) {
	if a.Validate() != nil {
		w.err = ErrInternal
		return
	}
	w.res.Artifacts = append(w.res.Artifacts, a)
}

func (w *walker) addFinding(k kind, sev finding.Severity, file string, meta map[string]any) {
	w.findings++
	f := finding.Finding{
		ID:          k.id + "-" + strconv.Itoa(w.findings),
		Severity:    sev,
		Category:    "ingest",
		Title:       k.title,
		Description: k.desc,
		File:        file,
		Metadata:    meta,
	}
	if f.Validate() != nil {
		w.err = ErrInternal
		return
	}
	w.res.Findings = append(w.res.Findings, f)
}

// result picks the outcome of a finished walk: a fatal error discards the
// partial Result, and an incomplete walk adds its one summary Finding.
func (w *walker) result() (Result, error) {
	incomplete := w.err == nil && w.c.incomplete()
	if incomplete {
		w.addIncomplete()
	}
	switch {
	case w.err != nil:
		return Result{}, w.err
	case incomplete:
		return w.res, ErrIncomplete
	}
	return w.res, nil
}

func (w *walker) addIncomplete() {
	w.addFinding(kindIncomplete, finding.SeverityMedium, "", map[string]any{
		"depth_skipped":  w.c.depthSkipped,
		"entries_capped": w.c.entriesCapped,
		"read_errors":    w.c.readErrors,
		"changed":        w.c.changed,
		"path_too_long":  w.c.pathTooLong,
	})
}

// listNames reads up to max names, in batches, until EOF or an error. On an
// error it returns the names read so far.
func listNames(dir *os.File, max int) ([]string, error) {
	var names []string
	for len(names) < max {
		batch, err := dir.Readdirnames(min(listBatch, max-len(names)))
		names = append(names, batch...)
		if err == io.EOF {
			return names, nil
		}
		if err != nil {
			return names, err
		}
	}
	return names, nil
}
