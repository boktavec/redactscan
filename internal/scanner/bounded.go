package scanner

import (
	"errors"
	"io"
)

// Fixed-text errors: the inner reader's error can carry a file path.
var (
	errBadOffset  = errors.New("scanner: negative read offset")
	errReadFailed = errors.New("scanner: read failed")
)

// boundedReader is the only reader a scanner receives. It hides the concrete
// type of the caller's reader (an *os.File would expose Chmod, Fd and Name),
// never reads at or past size, and never returns the inner reader's error.
type boundedReader struct {
	r    io.ReaderAt
	size int64
}

// ReadAt reads from the inner reader, clipped to [0, size). It reports io.EOF
// when the read ends at size, as io.ReaderAt requires for a short read.
func (b *boundedReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errBadOffset
	}
	if off >= b.size {
		return 0, io.EOF
	}
	clipped := false
	if remaining := b.size - off; int64(len(p)) > remaining {
		p = p[:remaining]
		clipped = true
	}

	n, err := b.r.ReadAt(p, off)
	if errors.Is(err, io.EOF) {
		err = io.EOF // never pass on a wrapped error: it can carry a path
	}
	switch {
	case n < 0 || n > len(p):
		return 0, errReadFailed
	case err != nil && err != io.EOF:
		return n, errReadFailed
	case n < len(p) && err == nil:
		return n, errReadFailed // breaks the io.ReaderAt contract
	case clipped && n == len(p):
		return n, io.EOF
	}
	return n, err
}
