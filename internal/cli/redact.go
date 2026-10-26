package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/boktavec/redactscan/internal/redactor"
	"github.com/boktavec/redactscan/internal/safefs"
)

const (
	stdinArg  = "-"
	stdinName = "stdin"
)

// writeSibling is a seam: tests replace it to inject results and to swap the
// input between open and write. Production never changes it.
var writeSibling = safefs.WriteSibling

// summaryMode selects what a successful run prints on stderr.
type summaryMode int

const (
	modeText  summaryMode = iota // default
	modeJSON                     // -json
	modeQuiet                    // -quiet
)

const writeNote = "redactscan: note: output may still contain uncovered secret formats\n"

func runRedact(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("redact", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	fl.Bool("summary", false, "") // deprecated no-op, kept so existing scripts still parse
	quiet := fl.Bool("quiet", false, "")
	jsonOut := fl.Bool("json", false, "")
	toStdout := fl.Bool("stdout", false, "")
	force := fl.Bool("force", false, "")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stdout, usageText)
			return exitOK
		}
		return usageError(stderr, "invalid arguments")
	}
	if fl.NArg() > 1 {
		return usageError(stderr, "expected at most one FILE argument (flags must come before FILE)")
	}

	if *quiet && *jsonOut {
		return usageError(stderr, "-quiet and -json cannot be used together")
	}
	mode := modeText
	switch {
	case *jsonOut:
		mode = modeJSON
	case *quiet:
		mode = modeQuiet
	}

	fromStdin := fl.NArg() == 0 || fl.Arg(0) == stdinArg
	path := fl.Arg(0)
	data, input, code := readInput(fromStdin, path, stdin, stderr)
	if code != exitOK {
		return code
	}

	res, err := redactor.Redact(data)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "redactscan: redaction refused: %s\n", refusalReason(err))
		return exitRefused
	}

	if !fromStdin && !*toStdout {
		return writeCleaned(path, input, res, mode, *force, stderr)
	}

	if len(res.Output) > 0 {
		if n, err := stdout.Write(res.Output); err != nil || n != len(res.Output) {
			_, _ = io.WriteString(stderr, "redactscan: cannot write output: write failed\n")
			return exitIO
		}
	}
	printSummary(stderr, mode, res.Counts)
	return exitOK
}

// printSummary writes the success summary for mode: nothing for modeQuiet.
// Write errors are ignored: the output is already written, so a closed stderr
// must not turn a success into a failure.
func printSummary(w io.Writer, mode summaryMode, counts map[redactor.Kind]int) {
	switch mode {
	case modeText:
		_, _ = fmt.Fprintf(w, "redactscan: %s\n", summaryText(counts))
	case modeJSON:
		if counts == nil {
			counts = map[redactor.Kind]int{}
		}
		// Marshal cannot fail for this type; if it did, print nothing rather
		// than an error text, since the output was already written.
		b, err := json.Marshal(struct {
			Counts map[redactor.Kind]int `json:"counts"`
		}{counts})
		if err != nil {
			return
		}
		_, _ = w.Write(append(b, '\n'))
	}
}

// writeCleaned writes res.Output beside path (see safefs.WriteSibling) and
// reports the result on stderr. Called only after Redact succeeded.
func writeCleaned(path string, input fs.FileInfo, res redactor.Result, mode summaryMode, force bool, stderr io.Writer) int {
	dir, base := splitTyped(path)
	out := strconv.Quote(dir + cleanedName(base))
	tempLeft, err := writeSibling(path, input, cleanedName(base), res.Output, force)
	if tempLeft {
		defer func() { _, _ = io.WriteString(stderr, "redactscan: temporary file may remain\n") }()
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "redactscan: cannot write %s: %s\n", out, writeReason(err, force))
		return exitIO
	}
	printSummary(stderr, mode, res.Counts)
	if mode == modeText {
		_, _ = fmt.Fprintf(stderr, "redactscan: wrote %s\n", out)
		_, _ = io.WriteString(stderr, writeNote)
	}
	return exitOK
}

// writeReason maps by sentinel or errno, never by safefs step name or OS text.
// ErrChanged is checked first: with replace, a rename onto a directory
// arrives as ErrChanged, not EEXIST.
func writeReason(err error, replace bool) string {
	var nre *safefs.NotRegularError
	switch {
	case errors.Is(err, safefs.ErrChanged):
		return "file changed during write"
	case !replace && errors.Is(err, syscall.EEXIST):
		return "already exists (use -force to replace)"
	case errors.Is(err, safefs.ErrSymlink):
		return "symlink refused"
	case errors.As(err, &nre):
		return "not a regular file (" + string(nre.Type) + ")"
	case errors.Is(err, syscall.ENOTSUP), errors.Is(err, syscall.EOPNOTSUPP), errors.Is(err, syscall.EMLINK),
		!replace && errors.Is(err, syscall.EPERM):
		// Without -force the only EPERM source is link on a filesystem without
		// hard links, and the step name is not available here by design.
		return "no-clobber write not supported on this filesystem"
	case errors.Is(err, syscall.EISDIR):
		// rename of a file onto an empty directory that appeared after the
		// pre-check (EEXIST, mapped to ErrChanged, covers a non-empty one).
		return "not a regular file (directory)"
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return "permission denied"
	case errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		return "no space left"
	case errors.Is(err, syscall.ENAMETOOLONG):
		return "name too long"
	case errors.Is(err, syscall.EROFS):
		return "read-only filesystem"
	case errors.Is(err, safefs.ErrUnsupportedPlatform):
		return "unsupported platform"
	default:
		return "write failed"
	}
}

// readInput reads at most MaxInputSize+1 bytes from stdin or from path. An
// empty path is not stdin. For a file it also returns the descriptor's
// FileInfo (nil for stdin). On failure it prints the message and returns
// exitIO.
func readInput(fromStdin bool, path string, stdin io.Reader, stderr io.Writer) ([]byte, fs.FileInfo, int) {
	r, name := stdin, stdinName
	var fi fs.FileInfo
	if !fromStdin {
		f, err := safefs.OpenRegular(path)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "redactscan: cannot open %s: %s\n", strconv.Quote(path), openReason(err))
			return nil, nil, exitIO
		}
		defer func() { _ = f.Close() }()
		r, name = f, strconv.Quote(path)
		if fi, err = f.Stat(); err != nil {
			_, _ = fmt.Fprintf(stderr, "redactscan: cannot read %s: read failed\n", name)
			return nil, nil, exitIO
		}
	}

	data, err := io.ReadAll(io.LimitReader(r, redactor.MaxInputSize+1))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "redactscan: cannot read %s: read failed\n", name)
		return nil, nil, exitIO
	}
	return data, fi, exitOK
}

func openReason(err error) string {
	var nre *safefs.NotRegularError
	switch {
	case errors.Is(err, safefs.ErrSymlink):
		return "symlink refused"
	case errors.As(err, &nre):
		return "not a regular file (" + string(nre.Type) + ")"
	case errors.Is(err, safefs.ErrNotRegular):
		return "not a regular file"
	case errors.Is(err, safefs.ErrChanged):
		return "file changed during open"
	case errors.Is(err, safefs.ErrUnsupportedPlatform):
		return "unsupported platform"
	case errors.Is(err, fs.ErrNotExist):
		return "not found"
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	default:
		return "cannot open"
	}
}

func refusalReason(err error) string {
	var ve *redactor.VerificationError
	switch {
	case errors.Is(err, redactor.ErrInputTooLarge):
		return "input exceeds 10 MiB limit"
	case errors.Is(err, redactor.ErrUnsupportedEncoding):
		return "unsupported encoding (NUL byte or UTF-16/32)"
	case errors.As(err, &ve):
		return "output could not be verified (kind: " + string(ve.Kind) + ")"
	case errors.Is(err, redactor.ErrVerificationFailed):
		return "output could not be verified (kind: unknown)"
	default:
		return "internal error"
	}
}

// summaryText lists secret kinds sorted by name, then label-like text that
// was neutralised.
func summaryText(counts map[redactor.Kind]int) string {
	var parts []string
	for kind, n := range counts {
		if kind != redactor.KindLabelLike {
			parts = append(parts, fmt.Sprintf("%s=%d", kind, n))
		}
	}
	sort.Strings(parts)

	text := "no covered secret formats found"
	if len(parts) > 0 {
		text = "redacted " + strings.Join(parts, " ")
	}
	if n := counts[redactor.KindLabelLike]; n > 0 {
		text += fmt.Sprintf("; neutralised %d label-like", n)
	}
	return text
}
