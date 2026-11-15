package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/report"
	"github.com/boktavec/redactscan/internal/safefs"
	"github.com/boktavec/redactscan/internal/scanner"
)

const exitIncomplete = 1 // the scan did not complete cleanly

const scanArtifactID = "file-1"

// defaultRegistry is a seam: tests replace it to inject scanners. Production
// never changes it.
var defaultRegistry = scanner.Default

// afterRun is a seam: tests replace it to modify the file between Run and the
// change checks. Production never changes it.
var afterRun = func() {}

// renderText and renderJSON are seams: tests replace them to inject renderer
// errors. Production never changes them.
var (
	renderText = report.Text
	renderJSON = report.JSON
)

func runScan(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("scan", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	asJSON := fl.Bool("json", false, "")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stdout, usageText)
			return exitOK
		}
		return usageError(stderr, "invalid arguments")
	}
	if fl.NArg() != 1 || fl.Arg(0) == stdinArg {
		return usageError(stderr, "scan expects exactly one FILE argument (flags must come before FILE)")
	}

	a, f, fi, code := openArtifact(fl.Arg(0), stderr)
	if code != exitOK {
		return code
	}
	defer func() { _ = f.Close() }()
	reg, err := defaultRegistry()
	if err != nil {
		_, _ = io.WriteString(stderr, "redactscan: internal error: invalid scanner registry\n")
		return exitIncomplete
	}
	res := reg.Run(context.Background(), a, f, a.Size)
	afterRun()
	// Scanners read the file live, so a change during the scan can give them
	// different bytes. The descriptor stays open until both checks are done.
	if !checkUnchanged(f, fi, a.Size) {
		res.Failures = append(res.Failures, scanner.Failure{Scanner: scanner.RegistryName, Reason: scanner.ReasonChanged})
	}

	render := renderText
	if *asJSON {
		render = renderJSON
	}
	if err := render(stdout, res); err != nil {
		if errors.Is(err, report.ErrWrite) {
			_, _ = io.WriteString(stderr, "redactscan: cannot write output: write failed\n")
		} else {
			_, _ = io.WriteString(stderr, "redactscan: internal error: cannot render report\n")
		}
		return exitIO
	}
	if res.Incomplete() {
		return exitIncomplete
	}
	return exitOK
}

// openArtifact opens path through safefs and describes it from one fstat of the
// opened descriptor, so size and mode belong to the file that is scanned.
// Nothing is read: scanners read through the returned file, which the caller
// closes, and the FileInfo for checkUnchanged. On failure it prints the message and returns exitIO.
func openArtifact(path string, stderr io.Writer) (artifact.Artifact, *os.File, fs.FileInfo, int) {
	f, err := safefs.OpenRegular(path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "redactscan: cannot open %s: %s\n", strconv.Quote(path), openReason(err))
		return artifact.Artifact{}, nil, nil, exitIO
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		_, _ = fmt.Fprintf(stderr, "redactscan: cannot read %s: read failed\n", strconv.Quote(path))
		return artifact.Artifact{}, nil, nil, exitIO
	}
	return artifact.Artifact{
		ID:           scanArtifactID,
		Path:         path,
		RelativePath: path,
		Name:         filepath.Base(path),
		Size:         fi.Size(),
		Mode:         fi.Mode().Perm(),
		Source:       artifact.SourceMetadata{Type: "file"},
	}, f, fi, exitOK
}

// checkUnchanged reports whether the open file still looks like before, the
// FileInfo that openArtifact took: the same size, mtime and ctime from a fresh
// fstat of the same descriptor, and no byte at offset size (an appended file,
// or a procfs file whose fstat size is 0 but which has content). Any failure to
// check counts as changed. It is best effort: it cannot see a same-size rewrite
// that leaves the timestamps alone (see the threat model).
func checkUnchanged(f *os.File, before fs.FileInfo, size int64) bool {
	after, err := f.Stat()
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return false
	}
	ctimeBefore, ok := ctimeNS(before)
	ctimeAfter, ok2 := ctimeNS(after)
	if !ok || !ok2 || ctimeBefore != ctimeAfter {
		return false
	}
	var probe [1]byte
	n, err := f.ReadAt(probe[:], size)
	return n == 0 && errors.Is(err, io.EOF)
}
