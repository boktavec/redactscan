// Package safefs is the filesystem trust boundary for input files: it opens
// only regular files reached without following a symlink, and refuses
// everything else with a fixed error. Error text never contains the path,
// file contents or OS error text.
package safefs

import (
	"errors"
	"io/fs"
)

var (
	ErrSymlink             = errors.New("safefs: symlink refused")
	ErrNotRegular          = errors.New("safefs: not a regular file")
	ErrChanged             = errors.New("safefs: file changed during open")
	ErrUnsupportedPlatform = errors.New("safefs: unsupported platform")
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

func fileType(m fs.FileMode) FileType {
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
	op  string // "lstat", "open", "fstat", "set blocking"
	err error
}

func (e *opError) Error() string { return "safefs: " + e.op + " failed" }
func (e *opError) Unwrap() error { return e.err }

// newOpError drops the *fs.PathError wrapper so the path cannot leak.
func newOpError(op string, err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return &opError{op: op, err: err}
}

// afterLstat runs between Lstat and open. Tests in this package replace it to
// swap the file on disk; production never changes it.
var afterLstat = func() {}
