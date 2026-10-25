package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/boktavec/redactscan/internal/redactor"
	"github.com/boktavec/redactscan/internal/safefs"
)

const (
	stdinArg  = "-"
	stdinName = "stdin"
)

func openInput(path string) (io.ReadCloser, error) {
	return safefs.OpenRegular(path)
}

func runRedact(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("redact", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	summary := fl.Bool("summary", false, "")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stdout, usageText)
			return exitOK
		}
		return usageError(stderr, "invalid arguments")
	}
	if fl.NArg() > 1 {
		return usageError(stderr, "expected at most one FILE argument")
	}

	data, code := readInput(fl.NArg() == 0 || fl.Arg(0) == stdinArg, fl.Arg(0), stdin, stderr)
	if code != exitOK {
		return code
	}

	res, err := redactor.Redact(data)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "redactscan: redaction refused: %s\n", refusalReason(err))
		return exitRefused
	}

	if len(res.Output) > 0 {
		if n, err := stdout.Write(res.Output); err != nil || n != len(res.Output) {
			_, _ = io.WriteString(stderr, "redactscan: cannot write output: write failed\n")
			return exitIO
		}
	}
	if *summary {
		_, _ = fmt.Fprintf(stderr, "redactscan: %s\n", summaryText(res.Counts))
	}
	return exitOK
}

// readInput reads at most MaxInputSize+1 bytes from stdin or from path. An
// empty path is passed to openInput like any other. On failure it prints the
// message and returns exitIO.
func readInput(fromStdin bool, path string, stdin io.Reader, stderr io.Writer) ([]byte, int) {
	r, name := stdin, stdinName
	if !fromStdin {
		f, err := openInput(path)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "redactscan: cannot open %s: %s\n", strconv.Quote(path), openReason(err))
			return nil, exitIO
		}
		defer func() { _ = f.Close() }()
		r, name = f, strconv.Quote(path)
	}

	data, err := io.ReadAll(io.LimitReader(r, redactor.MaxInputSize+1))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "redactscan: cannot read %s: read failed\n", name)
		return nil, exitIO
	}
	return data, exitOK
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
