package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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

	a, content, code := readArtifact(fl.Arg(0), stderr)
	if code != exitOK {
		return code
	}
	reg, err := defaultRegistry()
	if err != nil {
		_, _ = io.WriteString(stderr, "redactscan: internal error: invalid scanner registry\n")
		return exitIncomplete
	}
	res := reg.Run(context.Background(), a, content)

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

// readArtifact opens path through safefs and reads at most
// scanner.MaxContentSize+1 bytes, so an over-cap file is detectable without
// reading it all. On failure it prints the message and returns exitIO.
func readArtifact(path string, stderr io.Writer) (artifact.Artifact, []byte, int) {
	f, err := safefs.OpenRegular(path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "redactscan: cannot open %s: %s\n", strconv.Quote(path), openReason(err))
		return artifact.Artifact{}, nil, exitIO
	}
	defer func() { _ = f.Close() }()

	content, err := io.ReadAll(io.LimitReader(f, scanner.MaxContentSize+1))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "redactscan: cannot read %s: read failed\n", strconv.Quote(path))
		return artifact.Artifact{}, nil, exitIO
	}
	return artifact.Artifact{
		ID:           scanArtifactID,
		Path:         path,
		RelativePath: path,
		Name:         filepath.Base(path),
		Size:         int64(len(content)),
		Source:       artifact.SourceMetadata{Type: "file"},
	}, content, exitOK
}
