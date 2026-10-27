// Package safefs is the filesystem trust boundary for input and output files.
// OpenRegular opens only regular files reached without following a symlink.
// WriteSibling creates a new file beside an input through a pinned directory,
// without clobbering unless asked. OpenDirRoot and OpenChildDir open
// directories for traversal as pinned roots. All refuse everything unsafe with a fixed
// error. Error text never contains the path, file contents or OS error text.
package safefs

import (
	"errors"
	"io/fs"
	"os"
)

var (
	ErrSymlink             = errors.New("safefs: symlink refused")
	ErrNotRegular          = errors.New("safefs: not a regular file")
	ErrNotDir              = errors.New("safefs: not a directory")
	ErrChanged             = errors.New("safefs: file changed during open")
	ErrUnsupportedPlatform = errors.New("safefs: unsupported platform")
	ErrInvalidName         = errors.New("safefs: invalid output name")
	ErrTempNames           = errors.New("safefs: no free temporary name")
)

// FileType names the kind of non-regular file that was refused.
type FileType string

const (
	TypeDirectory FileType = "directory"
	TypeFIFO      FileType = "fifo"
	TypeDevice    FileType = "device" // character and block
	TypeSocket    FileType = "socket"
	TypeIrregular FileType = "irregular" // any other non-regular mode
)

// NotRegularError matches ErrNotRegular with errors.Is.
type NotRegularError struct{ Type FileType }

func (e *NotRegularError) Error() string {
	return "safefs: not a regular file (" + string(e.Type) + ")"
}

func (e *NotRegularError) Is(target error) bool { return target == ErrNotRegular }

// TypeOf names the kind of file a mode describes.
func TypeOf(m fs.FileMode) FileType {
	switch {
	case m.IsDir():
		return TypeDirectory
	case m&fs.ModeNamedPipe != 0:
		return TypeFIFO
	case m&(fs.ModeDevice|fs.ModeCharDevice) != 0:
		return TypeDevice
	case m&fs.ModeSocket != 0:
		return TypeSocket
	default:
		return TypeIrregular
	}
}

// opError has fixed text per step and unwraps to the bare syscall.Errno
// (never the *fs.PathError, which carries the path).
type opError struct {
	op  string // "lstat", "open", "fstat", "set blocking", "link", "rename", ...
	err error
}

func (e *opError) Error() string { return "safefs: " + e.op + " failed" }
func (e *opError) Unwrap() error { return e.err }

// StripPath returns the bare error inside a *fs.PathError, *os.LinkError or
// *os.SyscallError, or err itself otherwise. Those wrappers carry the path, so
// callers that build their own fixed-text errors drop them with this.
func StripPath(err error) error {
	var pe *fs.PathError
	var le *os.LinkError
	var se *os.SyscallError
	switch {
	case errors.As(err, &pe):
		return pe.Err
	case errors.As(err, &le):
		return le.Err
	case errors.As(err, &se):
		return se.Err
	}
	return err
}

func newOpError(op string, err error) error {
	return &opError{op: op, err: StripPath(err)}
}

// afterLstat runs between Lstat and open. Tests in this package replace it to
// swap the file on disk; production never changes it.
var afterLstat = func() {}
