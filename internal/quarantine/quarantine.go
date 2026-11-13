// Package quarantine is the on-disk store for suspicious content: one 0700
// directory per quarantine event under <base>/quarantine, holding the exact
// bytes (0600) and a metadata file whose presence marks the entry complete.
// See docs/features/quarantine-store/spec.md and ADR 0006.
//
// Name, URI and finding strings in Metadata are untrusted: output code must
// escape them, and callers must never format Metadata with %v, slog or JSON
// into errors or logs (log the ID only). Content bytes are never returned by
// Read. Error text is fixed: it never contains a path, ID, name, URI, finding
// text or OS error text, and OS errors unwrap to a bare syscall.Errno.
package quarantine

import (
	"errors"
	"io/fs"
	"os"
)

const (
	SchemaVersion        = 1
	MaxMetadataBytes     = 4 << 20   // Assumed placeholder; shared by Put and Read
	DefaultMaxEntrySize  = 256 << 20 // Assumed placeholder (spec D1)
	DefaultMaxStoreBytes = 4 << 30   // Assumed placeholder
	DefaultMaxEntries    = 1000      // Assumed placeholder
	MaxNameBytes         = 4096
	MaxURIBytes          = 8192
	MaxCategoryBytes     = 64
	MaxDescriptionBytes  = 1024
)

// Decision is the scan outcome that put content in quarantine. Only
// non-clean decisions exist: a store entry is never "allow".
type Decision string

const (
	Review Decision = "review"
	Block  Decision = "block"
)

var (
	ErrUnsupportedPlatform = errors.New("quarantine: unsupported platform")
	ErrInvalidBase         = errors.New("quarantine: invalid base directory")
	ErrInvalidOptions      = errors.New("quarantine: invalid options")
	ErrRunningAsRoot       = errors.New("quarantine: refusing to run as root without AllowRoot")
	ErrUnsafeDir           = errors.New("quarantine: unsafe store directory")
	ErrInvalidID           = errors.New("quarantine: invalid id")
	ErrNotFound            = errors.New("quarantine: entry not found")
	ErrIncomplete          = errors.New("quarantine: entry incomplete")
	ErrCorruptMetadata     = errors.New("quarantine: corrupt metadata")
	ErrMetadataTooLarge    = errors.New("quarantine: metadata too large")
	ErrInvalidInput        = errors.New("quarantine: invalid input")
	ErrSensitiveInput      = errors.New("quarantine: input contains sensitive data")
	ErrTooLarge            = errors.New("quarantine: content too large")
	ErrStoreFull           = errors.New("quarantine: store full")
	ErrSourceChanged       = errors.New("quarantine: source changed while copying")
	ErrIDExhausted         = errors.New("quarantine: no free entry id")
	ErrEntryExists         = errors.New("quarantine: entry already exists")
	ErrVerifyFailed        = errors.New("quarantine: verification failed")
)

// Options tunes the store limits. Zero values select the defaults.
type Options struct {
	MaxEntrySize  int64 // 0 => DefaultMaxEntrySize; negative => ErrInvalidOptions
	MaxStoreBytes int64 // 0 => DefaultMaxStoreBytes; negative => ErrInvalidOptions
	MaxEntries    int   // 0 => DefaultMaxEntries; negative => ErrInvalidOptions
	AllowRoot     bool  // permit euid 0 (explicit opt-in)
}

func (o Options) withDefaults() (Options, error) {
	if o.MaxEntrySize < 0 || o.MaxStoreBytes < 0 || o.MaxEntries < 0 {
		return Options{}, ErrInvalidOptions
	}
	if o.MaxEntrySize == 0 {
		o.MaxEntrySize = DefaultMaxEntrySize
	}
	if o.MaxStoreBytes == 0 {
		o.MaxStoreBytes = DefaultMaxStoreBytes
	}
	if o.MaxEntries == 0 {
		o.MaxEntries = DefaultMaxEntries
	}
	return o, nil
}

const (
	idHashLen   = 64
	idSuffixLen = 16
)

// ValidID reports whether id matches ^[0-9a-f]{64}-[0-9a-f]{16}$. The grammar
// cannot express ".", "..", "/" or NUL, so a valid ID is always one safe path
// component. Every function that takes an ID checks it before any I/O.
func ValidID(id string) bool {
	if len(id) != idHashLen+1+idSuffixLen || id[idHashLen] != '-' {
		return false
	}
	for i := 0; i < len(id); i++ {
		if i == idHashLen {
			continue
		}
		if c := id[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// opError has fixed text per step and unwraps to the bare syscall.Errno
// (never the *fs.PathError, which carries the path).
type opError struct {
	op  string
	err error
}

func (e *opError) Error() string { return "quarantine: " + e.op + " failed" }
func (e *opError) Unwrap() error { return e.err }

func newOpError(op string, err error) error {
	var pe *fs.PathError
	var le *os.LinkError
	var se *os.SyscallError
	switch {
	case errors.As(err, &pe):
		err = pe.Err
	case errors.As(err, &le):
		err = le.Err
	case errors.As(err, &se):
		err = se.Err
	}
	return &opError{op: op, err: err}
}
