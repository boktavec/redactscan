package scanner

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"testing"
)

// stubReader returns fixed results from ReadAt, whatever it is asked.
type stubReader struct {
	n    int
	err  error
	asks []int // len(p) of each call
}

func (s *stubReader) ReadAt(p []byte, _ int64) (int, error) {
	s.asks = append(s.asks, len(p))
	return s.n, s.err
}

func TestBoundedReaderOffsets(t *testing.T) {
	const size = 5
	newBounded := func() *boundedReader { return &boundedReader{strings.NewReader("abcdefghij"), size} }

	tests := []struct {
		name    string
		off     int64
		bufLen  int
		wantN   int
		wantErr error
		want    string
	}{
		{"negative offset", -1, 1, 0, errBadOffset, ""},
		{"min int offset", -1 << 63, 1, 0, errBadOffset, ""},
		{"at size", size, 1, 0, io.EOF, ""},
		{"past size", size + 3, 1, 0, io.EOF, ""},
		{"zero length at size", size, 0, 0, io.EOF, ""},
		{"inside, exact end", 2, 3, 3, nil, "cde"},
		{"clipped to size", 2, 8, 3, io.EOF, "cde"},
		{"whole content clipped", 0, 100, 5, io.EOF, "abcde"},
		{"inside, not at end", 0, 2, 2, nil, "ab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := make([]byte, tt.bufLen)
			n, err := newBounded().ReadAt(p, tt.off)
			if n != tt.wantN || err != tt.wantErr || string(p[:n]) != tt.want {
				t.Errorf("ReadAt = %d, %v, %q; want %d, %v, %q", n, err, p[:n], tt.wantN, tt.wantErr, tt.want)
			}
		})
	}
}

func TestBoundedReaderNeverAsksPastSize(t *testing.T) {
	inner := &stubReader{n: 3, err: io.EOF}
	b := &boundedReader{inner, 5}
	_, _ = b.ReadAt(make([]byte, 100), 2)
	if len(inner.asks) != 1 || inner.asks[0] != 3 {
		t.Errorf("inner asked for %v bytes, want [3]", inner.asks)
	}
}

func TestBoundedReaderInnerMisbehavior(t *testing.T) {
	const path = "/home/user/secret-name.txt"
	pathErr := &fs.PathError{Op: "read", Path: path, Err: errors.New("EIO")}

	tests := []struct {
		name  string
		inner *stubReader
		wantN int
		want  error
	}{
		{"reports more than asked", &stubReader{n: 9}, 0, errReadFailed},
		{"reports negative count", &stubReader{n: -1}, 0, errReadFailed},
		{"OS error with data", &stubReader{n: 2, err: pathErr}, 2, errReadFailed},
		{"OS error without data", &stubReader{n: 0, err: pathErr}, 0, errReadFailed},
		{"short read without error", &stubReader{n: 2}, 2, errReadFailed},
		{"PathError wrapping EOF, full read", &stubReader{n: 4, err: &fs.PathError{Op: "read", Path: path, Err: io.EOF}}, 4, io.EOF},
		{"PathError wrapping EOF, short read", &stubReader{n: 2, err: &fs.PathError{Op: "read", Path: path, Err: io.EOF}}, 2, io.EOF},
		{"wrapped EOF, full read", &stubReader{n: 4, err: fmt.Errorf("at "+path+": %w", io.EOF)}, 4, io.EOF},
		{"short read with EOF", &stubReader{n: 2, err: io.EOF}, 2, io.EOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := (&boundedReader{tt.inner, 10}).ReadAt(make([]byte, 4), 0)
			if n != tt.wantN || err != tt.want {
				t.Errorf("ReadAt = %d, %v; want %d, %v", n, err, tt.wantN, tt.want)
			}
			if err != nil && err != io.EOF && err != errReadFailed && err != errBadOffset {
				t.Errorf("error %v is not one of the allowed values", err)
			}
			var pe *fs.PathError
			if errors.As(err, &pe) || (err != nil && strings.Contains(err.Error(), path)) {
				t.Errorf("error leaks the inner error: %v", err)
			}
		})
	}
}
