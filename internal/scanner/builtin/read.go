package builtin

import (
	"errors"
	"io"
)

// errTruncated has fixed text: the reader's own error can carry a path.
var errTruncated = errors.New("builtin: content shorter than its size")

// readFull fills p from r at off. It succeeds when ReadAt returned len(p)
// bytes with a nil error or io.EOF (io.ReaderAt allows EOF with a full read at
// the end of the content). A short read, or a full read with any other error,
// is an error: the file ended before its recorded size (a sysfs file, or one
// truncated during the scan) or the read failed. It never returns or wraps the
// reader's error. Every builtin scanner reads through it.
func readFull(r io.ReaderAt, p []byte, off int64) error {
	if n, err := r.ReadAt(p, off); n != len(p) || (err != nil && err != io.EOF) {
		return errTruncated
	}
	return nil
}
