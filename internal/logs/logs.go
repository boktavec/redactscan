// Package logs adapts live log sources into streams of complete lines.
//
// Everything a source reads is untrusted, and LogEntry.Line is raw,
// UNREDACTED data. The stream contract:
//
//   - The channel returned by Read is unbuffered and is always closed
//     eventually: after ctx is done, or after a fatal error.
//   - Only the last entry may have a non-nil Err; such an entry has a nil Line,
//     Truncated false and Dropped 0. A channel that closes without an Err entry
//     closes only because ctx is done.
//   - A Line is always a complete line within the size cap. A line over the cap,
//     a line cut off by truncation or rotation, and the fragment of a line
//     already in progress when reading starts are never emitted. Each becomes one
//     marker (Truncated true, nil Line) carrying no content.
//   - Error text is fixed: it never contains the path, the label, line content
//     or OS error text. OS errors still unwrap to a bare syscall.Errno.
//
// The guarantee is "no partial line", not "a secret stays on one line": a PEM
// block or a wrapped token spans several entries. Callers must:
//
//   - redact with context across lines, not line by line in isolation;
//   - never expose Line outside the process (MCP, logs) before redaction;
//   - escape CR, NUL, ANSI and bidi characters before display;
//   - bound the number of concurrent Read calls: each costs one descriptor, one
//     goroutine and up to MaxLineBytes plus 32 KiB of memory;
//   - always cancel ctx when done, or the goroutine and descriptor stay pinned
//     by a blocked send;
//   - never use Dropped as a size for allocation.
package logs

import (
	"context"
	"errors"

	"github.com/boktavec/redactscan/internal/safefs"
)

// LogSource is a named origin of log lines.
type LogSource interface {
	// Name is a short label, never a path.
	Name() string
	// Read starts following the source until ctx is done or a fatal error
	// occurs. See the package documentation for the stream contract.
	Read(ctx context.Context, q Query) (<-chan LogEntry, error)
}

// Query selects where a Read starts.
type Query struct {
	FromStart bool // false: start at the current end of the source (tail -f)
}

// LogEntry is one complete line, one drop marker, or (last entry only) a fatal error.
type LogEntry struct {
	Source    string // the source label, never a path
	Line      []byte // raw, UNREDACTED line without the trailing "\n"; nil for markers and errors
	Truncated bool   // a line, or part of one, was dropped; Line is nil
	Dropped   int64  // bytes discarded when the marker was sent; a lower bound, never a size to allocate
	Err       error  // non-nil only on the final entry before close
}

var (
	ErrInvalidOptions = errors.New("logs: invalid options")
	ErrReopenRefused  = errors.New("logs: rotated file refused") // owner or link count differs
)

// opError has fixed text per step and unwraps to the bare syscall.Errno
// (never a *fs.PathError, which carries the path).
type opError struct {
	op  string // "stat", "lstat", "read"
	err error
}

func (e *opError) Error() string { return "logs: " + e.op + " failed" }
func (e *opError) Unwrap() error { return e.err }

func newOpError(op string, err error) error {
	return &opError{op: op, err: safefs.StripPath(err)}
}
