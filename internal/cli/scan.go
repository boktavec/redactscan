package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strconv"

	"github.com/boktavec/redactscan/internal/artifact"
	"github.com/boktavec/redactscan/internal/finding"
	"github.com/boktavec/redactscan/internal/safefs"
	"github.com/boktavec/redactscan/internal/scanner"
)

const exitIncomplete = 1 // the scan did not complete cleanly

const scanArtifactID = "file-1"

// defaultRegistry is a seam: tests replace it to inject scanners. Production
// never changes it.
var defaultRegistry = scanner.Default

// registryFailureText is the stderr text for failures not tied to a scanner.
var registryFailureText = map[scanner.Reason]string{
	scanner.ReasonTooLarge:        "file exceeds 10 MiB limit",
	scanner.ReasonInvalidArtifact: "invalid artifact",
	scanner.ReasonNoScanner:       "no scanner ran",
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("scan", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
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

	stdoutFailed := writeFindings(stdout, res.Findings)
	printFailures(stderr, res)
	switch {
	case stdoutFailed:
		_, _ = io.WriteString(stderr, "redactscan: cannot write output: write failed\n")
		return exitIO
	case res.Incomplete():
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

// writeFindings prints one line per finding with a single Write and reports
// whether the write failed. Only severity, ID, File, Line and Title are
// printed; the untrusted strings are quoted so control and bidi characters
// appear escaped.
func writeFindings(w io.Writer, findings []finding.Finding) (failed bool) {
	var buf bytes.Buffer
	for _, f := range findings {
		buf.WriteString(f.Severity.String())
		buf.WriteByte(' ')
		buf.WriteString(strconv.Quote(f.ID))
		buf.WriteByte(' ')
		buf.WriteString(strconv.Quote(f.File))
		if f.Line > 0 {
			buf.WriteString(":" + strconv.Itoa(f.Line))
		}
		buf.WriteByte(' ')
		buf.WriteString(strconv.Quote(f.Title))
		buf.WriteByte('\n')
	}
	if buf.Len() == 0 {
		return false
	}
	n, err := w.Write(buf.Bytes())
	return err != nil || n != buf.Len()
}

// printFailures writes one line per failure and the summary to stderr. Lines
// are built from validated scanner names and constant reasons only. Write
// errors are ignored: there is nowhere left to report them.
func printFailures(w io.Writer, res scanner.Result) {
	for _, fl := range res.Failures {
		text, ok := registryFailureText[fl.Reason]
		if fl.Scanner != scanner.RegistryName || !ok {
			text = fl.Scanner + ": " + string(fl.Reason)
		}
		_, _ = fmt.Fprintf(w, "redactscan: scan incomplete: %s\n", text)
	}
	state := "complete"
	if res.Incomplete() {
		state = "incomplete"
	}
	_, _ = fmt.Fprintf(w, "redactscan: scan %s: %d findings\n", state, len(res.Findings))
}
