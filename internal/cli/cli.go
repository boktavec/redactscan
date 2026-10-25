// Package cli implements the redactscan command line. It owns every message
// the program prints: messages are built from fixed text, redactor kind
// constants and quoted user-supplied paths, never from input bytes or from
// library or OS error text.
package cli

import (
	"fmt"
	"io"
)

// Exit codes.
const (
	exitOK      = 0
	exitRefused = 1 // the redactor refused to produce output
	exitUsage   = 2
	exitIO      = 3
)

const usageText = `Usage:
  redactscan redact [-summary] [-stdout] [-force] [FILE|-]

Replaces covered secret formats in FILE (or stdin when FILE is "-" or absent)
with numbered labels. Covered formats: AWS access keys, AWS secret keys,
GitHub tokens, PEM private keys. Other formats pass through unchanged.
Pre-existing label-like text such as [GITHUB_TOKEN_1] is rewritten with
parentheses. Input is limited to 10 MiB. With no FILE on a terminal the
command waits for input until end of file, like cat. FILE must be a regular
file reached without symlinks (on macOS the system links /tmp, /var and /etc
are allowed).

With FILE, the result is written to a new file next to FILE, named by adding
_cleaned before the last extension (app.log becomes app_cleaned.log, .env
becomes .env_cleaned), with mode 0600; stdout stays empty. An existing
destination is refused unless -force is given. Use -stdout to print to stdout
instead (BREAKING: older versions did this by default, so "redact f | cmd"
now receives nothing). Stdin always goes to stdout. Flags must come before
FILE.

Options:
  -summary  write a one-line count of replaced kinds to stderr
  -stdout   write the result to stdout instead of a file (FILE only)
  -force    replace an existing output file (file output only)

Exit codes:
  0  success, or help requested
  1  redaction refused (too large, unsupported encoding, output could not be
     verified, or internal error); nothing is written to stdout or to a file
  2  usage error
  3  I/O error (open, read, stdout write, or creating the output file),
     including a refused output destination
`

// Run executes redactscan with args (without the program name) and returns
// the process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usageError(stderr, "missing command")
	}
	switch args[0] {
	case "-h", "-help", "--help":
		_, _ = io.WriteString(stdout, usageText)
		return exitOK
	case "redact":
		return runRedact(args[1:], stdin, stdout, stderr)
	default:
		return usageError(stderr, fmt.Sprintf("unknown command %q", args[0]))
	}
}

func usageError(stderr io.Writer, reason string) int {
	_, _ = fmt.Fprintf(stderr, "redactscan: %s\n%s", reason, usageText)
	return exitUsage
}
